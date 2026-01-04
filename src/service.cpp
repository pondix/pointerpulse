#include "replicapulse/service.h"
#include "replicapulse/checkpoint.h"
#include "replicapulse/connection.h"
#include "replicapulse/event.h"
#include "replicapulse/ha.h"
#include "replicapulse/logging.h"
#include "replicapulse/parser.h"
#include "replicapulse/sql_formatter.h"
#include "replicapulse/table_metadata.h"
#include "replicapulse/gtid_tracker.h"
#include "replicapulse/threading.h"

#include <fstream>
#include <iostream>
#include <mutex>
#include <optional>
#include <thread>

namespace replicapulse {

struct AppContext {
    ReplicaPulseConfig config;
    TableMetadataCache cache;
    MySQLConnection metadata_conn;
    CheckpointManager *checkpoint{nullptr};
    std::mutex pos_mutex;
    std::string current_binlog;
    std::atomic<uint32_t> current_pos{4};
    std::optional<std::string> current_gtid;
    GtidTracker gtid_tracker;
};

static std::string escape_sql_string(const std::string &input) {
    std::string escaped;
    escaped.reserve(input.size() + 2);
    for (unsigned char c : input) {
        if (c == '\'') escaped += "''";
        else if (c == '\\') escaped += "\\\\";
        else escaped.push_back(static_cast<char>(c));
    }
    return escaped;
}

static bool fetch_table_metadata(AppContext &ctx, uint64_t table_id, const TableMapEvent &map) {
    if (!ctx.metadata_conn.is_connected()) return false;
    std::vector<std::vector<std::string>> rows;
    std::string query = "SELECT COLUMN_NAME, COLUMN_KEY FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='" +
                        escape_sql_string(map.schema) + "' AND TABLE_NAME='" + escape_sql_string(map.table) +
                        "' ORDER BY ORDINAL_POSITION";
    if (!ctx.metadata_conn.send_query(query, rows)) return false;
    TableMetadata meta;
    meta.schema = map.schema;
    meta.name = map.table;
    meta.column_types = map.column_types;
    meta.metadata = map.metadata;
    meta.nullable = map.null_bitmap;
    for (auto &r : rows) {
        meta.columns.push_back(r[0]);
        bool pk = (r[1] == "PRI");
        bool uniq = (r[1] == "UNI" || pk);
        meta.primary_key.push_back(pk);
        meta.unique_key.push_back(uniq);
    }
    ctx.cache.put(table_id, meta);
    return true;
}

int run_replicapulse(const ReplicaPulseConfig &config_in, const SqlSink &sink, std::atomic<bool> &stop) {
    LOG_INFO(LogCategory::SERVICE) << "run_replicapulse() starting";

    ReplicaPulseConfig config = config_in;
    CheckpointManager checkpoint_mgr(config.checkpoint_file);

    // Load checkpoint if no start position provided
    if (!config.start_position && !config.start_gtid_set) {
        LOG_DEBUG(LogCategory::CHECKPOINT) << "no start position, attempting checkpoint load from " << config.checkpoint_file;
        auto cp = checkpoint_mgr.load();
        if (cp) {
            LOG_INFO(LogCategory::CHECKPOINT) << "loaded checkpoint: " << cp->binlog_file << ":" << cp->position;
            config.start_position = StartPosition{cp->binlog_file, cp->position};
            if (cp->gtid_set && !config.start_gtid_set) {
                config.start_gtid_set = cp->gtid_set;
                LOG_DEBUG(LogCategory::CHECKPOINT) << "loaded gtid_set: " << *cp->gtid_set;
            }
        } else {
            LOG_DEBUG(LogCategory::CHECKPOINT) << "no checkpoint found";
        }
    }

    if (config.start_gtid_set && !config.start_position) {
        config.start_position = StartPosition{"", 4};
    }

    if (!config.start_position && !config.start_gtid_set) {
        LOG_ERROR(LogCategory::SERVICE) << "no start position or checkpoint available";
        return 1;
    }

    LOG_INFO(LogCategory::SERVICE) << "starting from binlog=" << config.start_position->binlog_file
                                   << " pos=" << config.start_position->position;

    AppContext ctx;
    ctx.config = config;
    ctx.checkpoint = &checkpoint_mgr;
    ctx.current_binlog = config.start_position->binlog_file;
    ctx.current_pos.store(config.start_position->position);
    if (config.start_gtid_set) {
        ctx.gtid_tracker.merge_executed(*config.start_gtid_set);
        LOG_DEBUG(LogCategory::SERVICE) << "initialized gtid tracker with: " << *config.start_gtid_set;
    }

    // HA coordination
    HaCoordinator ha(config.ha_lease_file, config.ha_node_id, std::chrono::seconds(config.ha_timeout_seconds));
    if (ha.enabled()) {
        LOG_INFO(LogCategory::SERVICE) << "waiting for HA lease at " << config.ha_lease_file;
        ha.acquire();
        LOG_INFO(LogCategory::SERVICE) << "HA lease acquired";
    }

    // Metadata connection (for column names)
    LOG_DEBUG(LogCategory::SERVICE) << "establishing metadata connection";
    ctx.metadata_conn.set_default_timeout_ms(config.io_timeout_ms);
    ctx.metadata_conn.set_use_tls(config.use_tls);
    if (!ctx.metadata_conn.connect_sql(config.host, config.port, config.user, config.password)) {
        LOG_WARN(LogCategory::SERVICE) << "metadata connection failed; proceeding without column names";
    } else {
        LOG_INFO(LogCategory::SERVICE) << "metadata connection established";
    }

    // Stream connection
    MySQLConnection stream_conn;
    stream_conn.set_default_timeout_ms(config.io_timeout_ms);
    stream_conn.set_use_tls(config.use_tls);

    auto connect_stream = [&]() {
        std::lock_guard<std::mutex> lk(ctx.pos_mutex);
        std::string resume_gtids = ctx.gtid_tracker.executed_string();

        LOG_DEBUG(LogCategory::SERVICE) << "connect_stream: binlog=" << ctx.current_binlog
                                        << " pos=" << ctx.current_pos.load()
                                        << " gtids=" << (resume_gtids.empty() ? "(none)" : resume_gtids);

        bool connected = false;
        if (!resume_gtids.empty()) {
            connected = stream_conn.connect_gtid(config.host, config.port, config.user, config.password, config.server_id,
                                            ctx.current_binlog, ctx.current_pos.load(), resume_gtids);
        } else if (config.start_gtid_set) {
            connected = stream_conn.connect_gtid(config.host, config.port, config.user, config.password, config.server_id,
                                            ctx.current_binlog, ctx.current_pos.load(), *config.start_gtid_set);
        } else {
            connected = stream_conn.connect(config.host, config.port, config.user, config.password, config.server_id,
                                   ctx.current_binlog, ctx.current_pos.load());
        }

        if (connected) {
            // Use a much longer timeout for binlog streaming (5 minutes)
            stream_conn.set_timeout_ms(300000);
            LOG_DEBUG(LogCategory::SERVICE) << "stream connection established, timeout set to 5 minutes";
        }
        return connected;
    };

    BoundedQueue<BinlogPacket> decode_queue(config.decode_queue_size);
    BoundedQueue<BinlogEvent> event_queue(config.work_queue_size);
    BoundedQueue<FormattedResult> output_queue(config.work_queue_size);

    BinlogParser parser;
    parser.set_table_cache(&ctx.cache);
    SqlFormatter formatter(ctx.cache, config.include_gtid, config.include_binlog_coords);

    LOG_INFO(LogCategory::SERVICE) << "starting worker threads: io, decode, " << config.worker_threads << " workers, output";

    // IO thread - reads binlog packets
    std::thread io_thread([&] {
        LOG_DEBUG(LogCategory::SERVICE) << "io_thread started";

        auto do_reconnect = [&](uint32_t &delay_ms) {
            while (!stop.load()) {
                LOG_INFO(LogCategory::CONNECTION) << "connecting to " << config.host << ":" << config.port << "...";
                if (connect_stream()) {
                    LOG_INFO(LogCategory::CONNECTION) << "connected successfully";
                    return true;
                }
                LOG_WARN(LogCategory::CONNECTION) << "connection failed, retrying in " << delay_ms << "ms";
                std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
                delay_ms = std::min(delay_ms * 2, config.reconnect_delay_max_ms);
            }
            LOG_INFO(LogCategory::SERVICE) << "io_thread: stop requested during reconnect";
            return false;
        };

        uint32_t backoff = config.reconnect_delay_ms;
        if (!do_reconnect(backoff)) {
            decode_queue.stop();
            LOG_DEBUG(LogCategory::SERVICE) << "io_thread exiting (initial connect failed)";
            return;
        }

        uint64_t packet_count = 0;
        while (!stop.load()) {
            BinlogPacket pkt;
            if (!stream_conn.read_binlog_packet(pkt)) {
                if (stop.load()) {
                    LOG_DEBUG(LogCategory::SERVICE) << "io_thread: stop requested";
                    break;
                }
                LOG_WARN(LogCategory::BINLOG) << "binlog read failed after " << packet_count << " packets, reconnecting";
                backoff = config.reconnect_delay_ms;
                if (!do_reconnect(backoff)) break;
                continue;
            }
            ++packet_count;
            if (packet_count % 1000 == 0) {
                LOG_DEBUG(LogCategory::BINLOG) << "received " << packet_count << " binlog packets";
            }
            if (!decode_queue.push(std::move(pkt))) {
                LOG_DEBUG(LogCategory::SERVICE) << "io_thread: decode_queue closed";
                break;
            }
        }
        decode_queue.stop();
        LOG_INFO(LogCategory::SERVICE) << "io_thread exiting, total packets: " << packet_count;
    });

    // Decode thread - parses binlog events
    std::thread decode_thread([&] {
        LOG_DEBUG(LogCategory::SERVICE) << "decode_thread started";
        BinlogPacket pkt;
        uint64_t seq = 1;
        uint64_t parse_errors = 0;

        while (decode_queue.pop(pkt)) {
            BinlogEvent evt;
            {
                std::lock_guard<std::mutex> lk(ctx.pos_mutex);
                evt.header.binlog_file = ctx.current_binlog;
                evt.header.start_position = ctx.current_pos.load();
            }

            if (!parser.parse_event(pkt.event_data, evt)) {
                ++parse_errors;
                LOG_WARN(LogCategory::PARSER) << "failed to parse binlog event #" << seq
                                              << " (total errors: " << parse_errors << ")";
                continue;
            }

            evt.seq_no = seq++;
            LOG_TRACE(LogCategory::PARSER) << "parsed event #" << evt.seq_no
                                           << " type=" << static_cast<int>(evt.header.type);

            if (evt.table_map) {
                fetch_table_metadata(ctx, evt.table_map->table_id, *evt.table_map);
            }

            {
                std::lock_guard<std::mutex> lk(ctx.pos_mutex);
                if (evt.rotate) {
                    LOG_INFO(LogCategory::BINLOG) << "rotate event: " << evt.rotate->next_binlog
                                                  << " pos=" << evt.rotate->position;
                    ctx.current_binlog = evt.rotate->next_binlog;
                    ctx.current_pos.store(static_cast<uint32_t>(evt.rotate->position));
                }
                if (evt.header.next_position) ctx.current_pos.store(evt.header.next_position);
                if (evt.previous_gtids) ctx.gtid_tracker.merge_executed(evt.previous_gtids->gtid_set);
                if (evt.gtid) {
                    ctx.current_gtid = evt.gtid->gtid;
                    ctx.gtid_tracker.on_gtid(*ctx.current_gtid);
                }
            }

            if ((evt.xid || (evt.query && !evt.rows)) && ctx.checkpoint) {
                if (ctx.gtid_tracker.pending()) {
                    ctx.gtid_tracker.on_commit();
                }
                Checkpoint cp;
                {
                    std::lock_guard<std::mutex> lk(ctx.pos_mutex);
                    cp.binlog_file = ctx.current_binlog;
                    cp.position = ctx.current_pos.load();
                    auto gtid_set_string = ctx.gtid_tracker.executed_string();
                    if (!gtid_set_string.empty()) cp.gtid_set = gtid_set_string;
                }
                ctx.checkpoint->store(cp);
                LOG_TRACE(LogCategory::CHECKPOINT) << "checkpoint saved: " << cp.binlog_file << ":" << cp.position;
            }

            if (!event_queue.push(std::move(evt))) {
                LOG_DEBUG(LogCategory::SERVICE) << "decode_thread: event_queue closed";
                break;
            }
        }
        event_queue.stop();
        LOG_INFO(LogCategory::SERVICE) << "decode_thread exiting, processed " << (seq - 1) << " events, " << parse_errors << " errors";
    });

    // Worker threads - format SQL
    std::vector<std::thread> workers;
    for (size_t i = 0; i < config.worker_threads; ++i) {
        workers.emplace_back([&, i] {
            LOG_DEBUG(LogCategory::SERVICE) << "worker_thread[" << i << "] started";
            BinlogEvent evt;
            uint64_t formatted = 0;

            while (event_queue.pop(evt)) {
                std::string sql;
                bool emitted = false;
                auto append = [&](const std::string &fragment) {
                    if (fragment.empty()) return;
                    if (!emitted) {
                        sql += formatter.format_event_prefix(evt.header);
                        emitted = true;
                    }
                    sql += fragment;
                };
                if (evt.gtid) {
                    append(formatter.format_gtid(*evt.gtid));
                    append(formatter.format_begin(evt.header));
                }
                if (evt.query) append(formatter.format_query(*evt.query, evt.header));
                if (evt.rows) append(formatter.format_rows_event(*evt.rows, evt.header));
                if (evt.xid) append(formatter.format_commit(evt.header));
                if (!sql.empty()) {
                    ++formatted;
                    FormattedResult res{evt.seq_no, sql};
                    if (!output_queue.push(std::move(res))) break;
                }
            }
            LOG_DEBUG(LogCategory::SERVICE) << "worker_thread[" << i << "] exiting, formatted " << formatted << " events";
        });
    }

    // Writer thread - outputs SQL
    std::thread writer_thread([&] {
        LOG_DEBUG(LogCategory::OUTPUT) << "writer_thread started";
        SqlSink resolved_sink = sink;
        std::ofstream file;
        if (!resolved_sink.stream && !resolved_sink.callback) {
            resolved_sink.stream = &std::cout;
        }
        if (config.output_path != "-" && sink.stream == nullptr) {
            LOG_INFO(LogCategory::OUTPUT) << "opening output file: " << config.output_path;
            file.open(config.output_path, std::ios::out | std::ios::app);
            if (!file.is_open()) {
                LOG_ERROR(LogCategory::OUTPUT) << "failed to open output file: " << config.output_path;
            }
            resolved_sink.stream = &file;
        }
        OrderedWriter writer;
        writer.consume(output_queue, resolved_sink);
        LOG_DEBUG(LogCategory::OUTPUT) << "writer_thread exiting";
    });

    // Wait for all threads
    LOG_DEBUG(LogCategory::SERVICE) << "waiting for io_thread";
    io_thread.join();
    LOG_DEBUG(LogCategory::SERVICE) << "waiting for decode_thread";
    decode_thread.join();
    LOG_DEBUG(LogCategory::SERVICE) << "waiting for worker threads";
    for (auto &t : workers) t.join();
    output_queue.stop();
    LOG_DEBUG(LogCategory::SERVICE) << "waiting for writer_thread";
    writer_thread.join();

    LOG_INFO(LogCategory::SERVICE) << "run_replicapulse() finished";
    return 0;
}

} // namespace replicapulse

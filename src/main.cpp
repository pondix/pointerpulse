#include "replicapulse/config.h"
#include "replicapulse/logging.h"
#include "replicapulse/service.h"

#include <atomic>
#include <iostream>
#include <csignal>
#include <sstream>

using namespace replicapulse;

static std::atomic<bool> *g_stop_flag = nullptr;

void handle_stop_signal(int) {
    if (g_stop_flag) g_stop_flag->store(true);
}

static void print_usage() {
    std::cerr << "Usage: replicapulse [OPTIONS]\n"
                 "  --host <host>                MySQL host (default: 127.0.0.1)\n"
                 "  --port <port>                MySQL port (default: 3306)\n"
                 "  --user <user>                Replication username (required)\n"
                 "  --password <password>        Replication password (required)\n"
                 "  --server-id <id>             Unique replication server-id (default: 1001)\n"
                 "  [--start-binlog <file> --start-pos <pos> | --start-gtid <set>] Optional binlog start position\n"
                 "  --checkpoint-file <path>     Checkpoint file for resume (default: replicapulse.checkpoint)\n"
                 "  --output <path|->            Output target path or '-' for stdout (default: -)\n"
                 "  --threads <n>                Worker threads (default: 4)\n"
                 "  --decode-queue-size <n>      Bounded decode queue size (default: 1024)\n"
                 "  --work-queue-size <n>        Bounded work queue size (default: 1024)\n"
                 "  --include-gtid|--no-gtid     Toggle GTID comment emission (default: include)\n"
                 "  --include-binlog-coords|--no-binlog-coords Toggle binlog coordinates (default: include)\n"
                 "  --ha-lease-file <path>       HA lease file (optional)\n"
                 "  --ha-node-id <id>            HA node identifier (default: replicapulse)\n"
                 "  --ha-timeout <seconds>       HA lease timeout (default: 15)\n"
                 "  --reconnect-delay-ms <ms>    Initial reconnect backoff (default: 500)\n"
                 "  --reconnect-delay-max-ms <ms>Max reconnect backoff (default: 8000)\n"
                 "  --io-timeout-ms <ms>         Socket IO timeout for reads/writes (default: 1000)\n"
                 "  --ssl                        Enable TLS\n"
                 "\n"
                 "Logging options:\n"
                 "  -q, --quiet                  Only show errors\n"
                 "  -v, --verbose                Enable verbose (debug) logging\n"
                 "  -vv, --trace                 Enable trace logging (very verbose)\n"
                 "  --log-category <cat>         Enable specific category (can repeat):\n"
                 "                               service, connection, handshake, binlog,\n"
                 "                               parser, query, output, checkpoint, all\n"
                 "\n"
                 "  -h, --help                   Show this help" << std::endl;
}

struct ParseResult {
    ReplicaPulseConfig cfg;
    bool show_help{false};
    std::string error;
};

static uint32_t parse_log_category(const std::string& cat) {
    if (cat == "service")    return static_cast<uint32_t>(LogCategory::SERVICE);
    if (cat == "connection") return static_cast<uint32_t>(LogCategory::CONNECTION);
    if (cat == "handshake")  return static_cast<uint32_t>(LogCategory::HANDSHAKE);
    if (cat == "binlog")     return static_cast<uint32_t>(LogCategory::BINLOG);
    if (cat == "parser")     return static_cast<uint32_t>(LogCategory::PARSER);
    if (cat == "query")      return static_cast<uint32_t>(LogCategory::QUERY);
    if (cat == "output")     return static_cast<uint32_t>(LogCategory::OUTPUT);
    if (cat == "checkpoint") return static_cast<uint32_t>(LogCategory::CHECKPOINT);
    if (cat == "all")        return static_cast<uint32_t>(LogCategory::ALL);
    return 0;
}

ParseResult parse_args(int argc, char **argv) {
    ParseResult result;
    ReplicaPulseConfig &cfg = result.cfg;
    bool category_set = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) return "";
            return argv[++i];
        };
        auto ensure_value = [&](const std::string &value, const std::string &flag) {
            if (value.empty()) {
                result.error = "Missing value for " + flag;
            }
            return value;
        };
        if (arg == "--host") cfg.host = ensure_value(next(), arg);
        else if (arg == "--port") cfg.port = static_cast<uint16_t>(std::stoi(ensure_value(next(), arg)));
        else if (arg == "--user") cfg.user = ensure_value(next(), arg);
        else if (arg == "--password") cfg.password = ensure_value(next(), arg);
        else if (arg == "--server-id") cfg.server_id = static_cast<uint32_t>(std::stoul(ensure_value(next(), arg)));
        else if (arg == "--start-binlog") {
            if (!cfg.start_position) cfg.start_position.emplace();
            cfg.start_position->binlog_file = ensure_value(next(), arg);
        } else if (arg == "--start-pos") {
            if (!cfg.start_position) cfg.start_position.emplace();
            cfg.start_position->position = static_cast<uint32_t>(std::stoul(ensure_value(next(), arg)));
        } else if (arg == "--start-gtid") {
            cfg.start_gtid_set = ensure_value(next(), arg);
        } else if (arg == "--output") cfg.output_path = ensure_value(next(), arg);
        else if (arg == "--threads") cfg.worker_threads = static_cast<size_t>(std::stoul(ensure_value(next(), arg)));
        else if (arg == "--checkpoint-file") cfg.checkpoint_file = ensure_value(next(), arg);
        else if (arg == "--ha-lease-file") cfg.ha_lease_file = ensure_value(next(), arg);
        else if (arg == "--ha-node-id") cfg.ha_node_id = ensure_value(next(), arg);
        else if (arg == "--ha-timeout") cfg.ha_timeout_seconds = static_cast<uint32_t>(std::stoul(ensure_value(next(), arg)));
        else if (arg == "--reconnect-delay-ms") cfg.reconnect_delay_ms = static_cast<uint32_t>(std::stoul(ensure_value(next(), arg)));
        else if (arg == "--reconnect-delay-max-ms") cfg.reconnect_delay_max_ms = static_cast<uint32_t>(std::stoul(ensure_value(next(), arg)));
        else if (arg == "--io-timeout-ms") cfg.io_timeout_ms = static_cast<uint32_t>(std::stoul(ensure_value(next(), arg)));
        else if (arg == "--ssl") cfg.use_tls = true;
        else if (arg == "--decode-queue-size") cfg.decode_queue_size = static_cast<size_t>(std::stoul(ensure_value(next(), arg)));
        else if (arg == "--work-queue-size") cfg.work_queue_size = static_cast<size_t>(std::stoul(ensure_value(next(), arg)));
        else if (arg == "--include-gtid") cfg.include_gtid = true;
        else if (arg == "--no-gtid") cfg.include_gtid = false;
        else if (arg == "--include-binlog-coords") cfg.include_binlog_coords = true;
        else if (arg == "--no-binlog-coords") cfg.include_binlog_coords = false;
        // Logging options
        else if (arg == "-q" || arg == "--quiet") cfg.log_verbosity = LogVerbosity::QUIET;
        else if (arg == "-v" || arg == "--verbose") cfg.log_verbosity = LogVerbosity::VERBOSE;
        else if (arg == "-vv" || arg == "--trace") cfg.log_verbosity = LogVerbosity::TRACE;
        else if (arg == "--log-category") {
            std::string cat = ensure_value(next(), arg);
            uint32_t cat_val = parse_log_category(cat);
            if (cat_val == 0) {
                result.error = "Unknown log category: " + cat;
            } else {
                if (!category_set) {
                    cfg.log_categories = 0;
                    category_set = true;
                }
                cfg.log_categories |= cat_val;
            }
        }
        else if (arg == "--help" || arg == "-h") result.show_help = true;
        else {
            result.error = "Unknown argument: " + arg;
        }

        if (!result.error.empty()) break;
    }
    if (result.error.empty()) {
        if (cfg.user.empty()) {
            result.error = "Replication user (--user) is required";
        } else if (cfg.password.empty()) {
            result.error = "Replication password (--password) is required";
        }
    }
    return result;
}

static void configure_logging(const ReplicaPulseConfig& config) {
    Logger& logger = Logger::instance();

    // Set log level based on verbosity
    switch (config.log_verbosity) {
        case LogVerbosity::QUIET:
            logger.set_level(LogLevel::ERROR);
            break;
        case LogVerbosity::NORMAL:
            logger.set_level(LogLevel::ERROR | LogLevel::WARN | LogLevel::INFO);
            break;
        case LogVerbosity::VERBOSE:
            logger.set_level(LogLevel::ERROR | LogLevel::WARN | LogLevel::INFO | LogLevel::DEBUG);
            break;
        case LogVerbosity::TRACE:
            logger.set_level(LogLevel::ALL);
            break;
    }

    // Set categories
    logger.set_categories(static_cast<LogCategory>(config.log_categories));
}

int main(int argc, char **argv) {
    ParseResult parsed = parse_args(argc, argv);
    if (parsed.show_help) {
        print_usage();
        return 0;
    }
    if (!parsed.error.empty()) {
        std::cerr << parsed.error << std::endl;
        print_usage();
        return 1;
    }

    ReplicaPulseConfig config = parsed.cfg;

    // Configure logging before anything else
    configure_logging(config);

    LOG_INFO(LogCategory::SERVICE) << "replicapulse starting";
    LOG_INFO(LogCategory::SERVICE) << "host=" << config.host << " port=" << config.port
                                   << " user=" << config.user << " server_id=" << config.server_id;

    if (config.start_position) {
        LOG_INFO(LogCategory::SERVICE) << "start position: " << config.start_position->binlog_file
                                       << ":" << config.start_position->position;
    }
    if (config.start_gtid_set) {
        LOG_INFO(LogCategory::SERVICE) << "start GTID set: " << *config.start_gtid_set;
    }
    if (!config.start_position && !config.start_gtid_set) {
        LOG_INFO(LogCategory::SERVICE) << "no start position provided; will attempt checkpoint resume";
    }

    std::atomic<bool> stop{false};
    g_stop_flag = &stop;
    std::signal(SIGINT, handle_stop_signal);
    std::signal(SIGTERM, handle_stop_signal);

    SqlSink sink;
    if (config.output_path == "-") {
        sink.stream = &std::cout;
    }

    LOG_DEBUG(LogCategory::SERVICE) << "output=" << config.output_path
                                    << " checkpoint=" << config.checkpoint_file;

    return run_replicapulse(config, sink, stop);
}

#include "replicapulse/config.h"
#include "replicapulse/service.h"

#include <atomic>
#include <iostream>
#include <csignal>

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
                 "  --debug                      Enable debug logging\n"
                 "  -h, --help                   Show this help" << std::endl;
}

struct ParseResult {
    ReplicaPulseConfig cfg;
    bool show_help{false};
    std::string error;
};

ParseResult parse_args(int argc, char **argv) {
    ParseResult result;
    ReplicaPulseConfig &cfg = result.cfg;
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
        else if (arg == "--debug") cfg.debug = true;
        else if (arg == "--decode-queue-size") cfg.decode_queue_size = static_cast<size_t>(std::stoul(ensure_value(next(), arg)));
        else if (arg == "--work-queue-size") cfg.work_queue_size = static_cast<size_t>(std::stoul(ensure_value(next(), arg)));
        else if (arg == "--include-gtid") cfg.include_gtid = true;
        else if (arg == "--no-gtid") cfg.include_gtid = false;
        else if (arg == "--include-binlog-coords") cfg.include_binlog_coords = true;
        else if (arg == "--no-binlog-coords") cfg.include_binlog_coords = false;
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
    if (!config.start_position && !config.start_gtid_set) {
        std::cerr << "no start position provided; will attempt checkpoint resume" << std::endl;
    }

    std::atomic<bool> stop{false};
    g_stop_flag = &stop;
    std::signal(SIGINT, handle_stop_signal);
    std::signal(SIGTERM, handle_stop_signal);

    SqlSink sink;
    if (config.output_path == "-") {
        sink.stream = &std::cout;
    }
    return run_replicapulse(config, sink, stop);
}

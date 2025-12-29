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
    std::cerr << "Usage: replicapulse --host h --port p --user u --password pw --server-id id "
                 "[--start-binlog file --start-pos pos | --start-gtid gtid_set]" << std::endl;
}


ReplicaPulseConfig parse_args(int argc, char **argv) {
    ReplicaPulseConfig cfg;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) return "";
            return argv[++i];
        };
        if (arg == "--host") cfg.host = next();
        else if (arg == "--port") cfg.port = static_cast<uint16_t>(std::stoi(next()));
        else if (arg == "--user") cfg.user = next();
        else if (arg == "--password") cfg.password = next();
        else if (arg == "--server-id") cfg.server_id = static_cast<uint32_t>(std::stoul(next()));
        else if (arg == "--start-binlog") {
            if (!cfg.start_position) cfg.start_position.emplace();
            cfg.start_position->binlog_file = next();
        } else if (arg == "--start-pos") {
            if (!cfg.start_position) cfg.start_position.emplace();
            cfg.start_position->position = static_cast<uint32_t>(std::stoul(next()));
        } else if (arg == "--start-gtid") {
            cfg.start_gtid_set = next();
        } else if (arg == "--output") cfg.output_path = next();
        else if (arg == "--threads") cfg.worker_threads = static_cast<size_t>(std::stoul(next()));
        else if (arg == "--checkpoint-file") cfg.checkpoint_file = next();
        else if (arg == "--ha-lease-file") cfg.ha_lease_file = next();
        else if (arg == "--ha-node-id") cfg.ha_node_id = next();
        else if (arg == "--ha-timeout") cfg.ha_timeout_seconds = static_cast<uint32_t>(std::stoul(next()));
        else if (arg == "--reconnect-delay-ms") cfg.reconnect_delay_ms = static_cast<uint32_t>(std::stoul(next()));
        else if (arg == "--reconnect-delay-max-ms") cfg.reconnect_delay_max_ms = static_cast<uint32_t>(std::stoul(next()));
        else if (arg == "--io-timeout-ms") cfg.io_timeout_ms = static_cast<uint32_t>(std::stoul(next()));
        else if (arg == "--decode-queue-size") cfg.decode_queue_size = static_cast<size_t>(std::stoul(next()));
        else if (arg == "--work-queue-size") cfg.work_queue_size = static_cast<size_t>(std::stoul(next()));
        else if (arg == "--include-gtid") cfg.include_gtid = true;
        else if (arg == "--no-gtid") cfg.include_gtid = false;
        else if (arg == "--include-binlog-coords") cfg.include_binlog_coords = true;
        else if (arg == "--no-binlog-coords") cfg.include_binlog_coords = false;
    }
    return cfg;
}

int main(int argc, char **argv) {
    ReplicaPulseConfig config = parse_args(argc, argv);
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

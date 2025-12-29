#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>

namespace replicapulse {

struct StartPosition {
    std::string binlog_file;
    uint32_t position{4};
};

struct ReplicaPulseConfig {
    std::string host{"127.0.0.1"};
    uint16_t port{3306};
    std::string user;
    std::string password;
    uint32_t server_id{1001};

    std::optional<StartPosition> start_position;
    std::optional<std::string> start_gtid_set;

    std::string checkpoint_file{"replicapulse.checkpoint"};
    std::string output_path{"-"};

    // High-availability lease (optional shared file-based lease)
    std::string ha_lease_file;
    std::string ha_node_id{"replicapulse"};
    uint32_t ha_timeout_seconds{15};

    // Reconnection/backoff tuning
    uint32_t reconnect_delay_ms{500};
    uint32_t reconnect_delay_max_ms{8000};
    uint32_t io_timeout_ms{1000};

    bool use_tls{false};

    bool include_gtid{true};
    bool include_binlog_coords{true};

    size_t decode_queue_size{1024};
    size_t work_queue_size{1024};
    size_t worker_threads{4};
};

} // namespace replicapulse

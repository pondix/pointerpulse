#pragma once

#include "config.h"

#include <mutex>
#include <optional>
#include <string>

namespace replicapulse {

struct Checkpoint {
    std::string binlog_file;
    uint32_t position{4};
    std::optional<std::string> gtid_set;
};

class CheckpointManager {
public:
    explicit CheckpointManager(std::string path);

    std::optional<Checkpoint> load();
    void store(const Checkpoint &cp);

private:
    std::string path_;
    std::mutex mu_;
};

} // namespace replicapulse


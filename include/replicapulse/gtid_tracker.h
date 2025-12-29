#pragma once

#include "replicapulse/gtid_set.h"

#include <optional>
#include <string>

namespace replicapulse {

class GtidTracker {
public:
    void merge_executed(const std::string &set_string);
    void on_gtid(const std::string &gtid);
    void on_commit();

    std::string executed_string() const { return executed_.to_string(); }
    std::optional<std::string> pending() const { return pending_gtid_; }

private:
    GtidSet executed_;
    std::optional<std::string> pending_gtid_;
};

} // namespace replicapulse

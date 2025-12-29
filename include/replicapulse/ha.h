#pragma once

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

namespace replicapulse {

// A minimal file-based lease for active/passive HA. Nodes periodically
// update the lease file with a heartbeat. A challenger will acquire the
// lease if the last heartbeat is older than the timeout.
class HaCoordinator {
public:
    HaCoordinator(std::string lease_file, std::string node_id, std::chrono::seconds timeout);
    ~HaCoordinator();

    // Blocks until the lease is acquired. Returns false if the coordinator
    // is disabled (empty lease file path).
    bool acquire();
    bool enabled() const { return !lease_file_.empty(); }

private:
    bool try_takeover();
    void heartbeat_loop();

    std::string lease_file_;
    std::string node_id_;
    std::chrono::seconds timeout_;
    std::atomic<bool> stop_{false};
    std::thread heartbeat_;
};

} // namespace replicapulse


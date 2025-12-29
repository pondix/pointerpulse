#include "replicapulse/ha.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <thread>

namespace replicapulse {

HaCoordinator::HaCoordinator(std::string lease_file, std::string node_id, std::chrono::seconds timeout)
    : lease_file_(std::move(lease_file)), node_id_(std::move(node_id)), timeout_(timeout) {}

HaCoordinator::~HaCoordinator() {
    stop_.store(true);
    if (heartbeat_.joinable()) heartbeat_.join();
}

bool HaCoordinator::try_takeover() {
    using clock = std::chrono::system_clock;
    const auto now = clock::to_time_t(clock::now());

    std::ifstream in(lease_file_);
    if (in.good()) {
        std::string owner;
        time_t ts;
        in >> owner >> ts;
        if (!in.fail() && (now - ts) < static_cast<time_t>(timeout_.count()) && owner != node_id_) {
            return false; // Lease is still fresh
        }
    }

    std::ofstream out(lease_file_, std::ios::trunc);
    if (!out.good()) return false;
    out << node_id_ << " " << now;
    return true;
}

bool HaCoordinator::acquire() {
    if (!enabled()) return false;
    while (!stop_.load()) {
        if (try_takeover()) {
            heartbeat_ = std::thread(&HaCoordinator::heartbeat_loop, this);
            return true;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return false;
}

void HaCoordinator::heartbeat_loop() {
    using clock = std::chrono::system_clock;
    while (!stop_.load()) {
        std::ofstream out(lease_file_, std::ios::trunc);
        if (out.good()) {
            out << node_id_ << " " << clock::to_time_t(clock::now());
        } else {
            std::cerr << "warning: failed to refresh HA lease at " << lease_file_ << std::endl;
        }
        std::this_thread::sleep_for(timeout_ / 2);
    }
}

} // namespace replicapulse


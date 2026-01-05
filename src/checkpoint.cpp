#include "replicapulse/checkpoint.h"

#include <chrono>
#include <fstream>
#include <iostream>

namespace replicapulse {

CheckpointManager::CheckpointManager(std::string path) : path_(std::move(path)) {}

std::optional<Checkpoint> CheckpointManager::load() {
    std::lock_guard<std::mutex> lock(mu_);
    std::ifstream in(path_);
    if (!in.good()) return std::nullopt;
    Checkpoint cp;
    in >> cp.binlog_file >> cp.position;
    if (!in.fail() && !cp.binlog_file.empty()) {
        std::string gtid;
        if (in >> gtid) cp.gtid_set = gtid;
        return cp;
    }
    return std::nullopt;
}

void CheckpointManager::store(const Checkpoint &cp) {
    std::lock_guard<std::mutex> lock(mu_);
    std::string tmp = path_ + ".tmp";
    std::ofstream out(tmp, std::ios::trunc);
    if (!out.good()) {
        std::cerr << "failed to write checkpoint to " << tmp << std::endl;
        return;
    }
    out << cp.binlog_file << " " << cp.position;
    if (cp.gtid_set) out << " " << *cp.gtid_set;
    out.flush();
    out.close();
    if (std::rename(tmp.c_str(), path_.c_str()) != 0) {
        std::cerr << "failed to rename checkpoint from " << tmp << " to " << path_ << std::endl;
    }
}

} // namespace replicapulse


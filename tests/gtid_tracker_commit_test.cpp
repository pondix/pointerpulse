#include "replicapulse/gtid_tracker.h"

#include <cassert>
#include <string>

using namespace replicapulse;

int main() {
    GtidTracker tracker;
    tracker.merge_executed("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:1-5");

    tracker.on_gtid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:6");
    // Should not include pending GTID until commit fires
    std::string before_commit = tracker.executed_string();
    assert(before_commit.find("6") == std::string::npos);

    tracker.on_commit();
    std::string after_commit = tracker.executed_string();
    assert(after_commit.find("6") != std::string::npos);

    tracker.on_gtid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:7");
    tracker.on_gtid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:8");
    // Only last pending should apply
    tracker.on_commit();
    std::string merged = tracker.executed_string();
    assert(merged.find("8") != std::string::npos);
    return 0;
}

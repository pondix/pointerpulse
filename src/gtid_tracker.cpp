#include "replicapulse/gtid_tracker.h"

namespace replicapulse {

void GtidTracker::merge_executed(const std::string &set_string) {
    executed_.merge_set(set_string);
}

void GtidTracker::on_gtid(const std::string &gtid) {
    pending_gtid_ = gtid;
}

void GtidTracker::on_commit() {
    if (pending_gtid_) {
        executed_.add_gtid(*pending_gtid_);
        pending_gtid_.reset();
    }
}

} // namespace replicapulse

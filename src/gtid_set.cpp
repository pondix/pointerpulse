#include "replicapulse/gtid_set.h"

#include <algorithm>
#include <cstdlib>
#include <sstream>

namespace replicapulse {

namespace {
std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> parts;
    std::string current;
    for (char c : s) {
        if (c == delim) {
            parts.push_back(current);
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    parts.push_back(current);
    return parts;
}
} // namespace

void GtidSet::add_interval(const std::string &sid, uint64_t start, uint64_t end) {
    if (start == 0 || end == 0 || end < start) return;
    auto &vec = intervals_[sid];
    vec.push_back({start, end});
    std::sort(vec.begin(), vec.end(), [](const Interval &a, const Interval &b) { return a.start < b.start; });
    std::vector<Interval> merged;
    for (const auto &iv : vec) {
        if (merged.empty() || iv.start > merged.back().end + 1) {
            merged.push_back(iv);
        } else {
            merged.back().end = std::max(merged.back().end, iv.end);
        }
    }
    vec.swap(merged);
}

void GtidSet::add_gtid(const std::string &gtid) {
    auto pos = gtid.find(':');
    if (pos == std::string::npos) return;
    std::string sid = gtid.substr(0, pos);
    std::string seq_str = gtid.substr(pos + 1);
    uint64_t seq = std::strtoull(seq_str.c_str(), nullptr, 10);
    add_interval(sid, seq, seq);
}

void GtidSet::merge_set(const std::string &set_string) {
    if (set_string.empty()) return;
    auto sid_sections = split(set_string, ',');
    for (const auto &section : sid_sections) {
        auto first_colon = section.find(':');
        if (first_colon == std::string::npos) continue;
        std::string sid = section.substr(0, first_colon);
        std::string intervals_part = section.substr(first_colon + 1);
        auto intervals = split(intervals_part, ':');
        for (const auto &iv : intervals) {
            if (iv.empty()) continue;
            auto dash = iv.find('-');
            uint64_t start = 0;
            uint64_t end = 0;
            if (dash == std::string::npos) {
                start = end = std::strtoull(iv.c_str(), nullptr, 10);
            } else {
                start = std::strtoull(iv.substr(0, dash).c_str(), nullptr, 10);
                end = std::strtoull(iv.substr(dash + 1).c_str(), nullptr, 10);
            }
            add_interval(sid, start, end == 0 ? start : end);
        }
    }
}

std::string GtidSet::to_string() const {
    std::vector<std::string> sids;
    sids.reserve(intervals_.size());
    for (const auto &kv : intervals_) sids.push_back(kv.first);
    std::sort(sids.begin(), sids.end());

    std::ostringstream out;
    bool first_sid = true;
    for (const auto &sid : sids) {
        auto it = intervals_.find(sid);
        if (it == intervals_.end()) continue;
        if (!first_sid) out << ',';
        first_sid = false;
        out << sid;
        for (const auto &iv : it->second) {
            out << ':' << iv.start << '-' << iv.end;
        }
    }
    return out.str();
}

} // namespace replicapulse

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace replicapulse {

class GtidSet {
public:
    void add_gtid(const std::string &gtid);
    void merge_set(const std::string &set_string);
    std::string to_string() const;
    bool empty() const { return intervals_.empty(); }

private:
    struct Interval {
        uint64_t start{0};
        uint64_t end{0}; // inclusive
    };

    void add_interval(const std::string &sid, uint64_t start, uint64_t end);

    std::unordered_map<std::string, std::vector<Interval>> intervals_;
};

} // namespace replicapulse

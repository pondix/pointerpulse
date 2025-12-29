#pragma once

#include "threading.h"

#include <cstdint>
#include <functional>
#include <map>
#include <ostream>
#include <string>

namespace replicapulse {

struct FormattedResult {
    uint64_t sequence{0};
    std::string sql;
};

struct SqlSink {
    std::ostream *stream{nullptr};
    std::function<void(const std::string &)> callback;
};

// OrderedWriter consumes formatted results and writes them in ascending
// sequence order, buffering out-of-order items until gaps are filled.
class OrderedWriter {
public:
    explicit OrderedWriter(uint64_t start_sequence = 1) : next_sequence_(start_sequence) {}

    void consume(BoundedQueue<FormattedResult> &queue, const SqlSink &sink);

private:
    void flush_ready(const SqlSink &sink);
    void emit(const std::string &sql, const SqlSink &sink);

    uint64_t next_sequence_{1};
    std::map<uint64_t, std::string> pending_;
};

} // namespace replicapulse


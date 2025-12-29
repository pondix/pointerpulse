#include "replicapulse/output.h"

namespace replicapulse {

void OrderedWriter::emit(const std::string &sql, const SqlSink &sink) {
    if (sink.callback) sink.callback(sql);
    if (sink.stream) {
        (*sink.stream) << sql;
        sink.stream->flush();
    }
}

void OrderedWriter::flush_ready(const SqlSink &sink) {
    while (!pending_.empty() && pending_.begin()->first == next_sequence_) {
        emit(pending_.begin()->second, sink);
        pending_.erase(pending_.begin());
        ++next_sequence_;
    }
}

void OrderedWriter::consume(BoundedQueue<FormattedResult> &queue, const SqlSink &sink) {
    FormattedResult res;
    while (queue.pop(res)) {
        pending_.emplace(res.sequence, res.sql);
        flush_ready(sink);
    }
    flush_ready(sink);
}

} // namespace replicapulse


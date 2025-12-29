#include "replicapulse/checkpoint.h"
#include "replicapulse/output.h"
#include "replicapulse/threading.h"

#include <cassert>
#include <filesystem>
#include <sstream>
#include <thread>

using namespace replicapulse;

int main() {
    // GTID-aware checkpoint persistence
    std::filesystem::path tmp = std::filesystem::temp_directory_path() / "replicapulse_checkpoint_gtid.txt";
    CheckpointManager mgr(tmp.string());
    Checkpoint to_store{"mysql-bin.000009", 12345, std::string("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:1-9")};
    mgr.store(to_store);
    auto loaded = mgr.load();
    assert(loaded.has_value());
    assert(loaded->binlog_file == to_store.binlog_file);
    assert(loaded->position == to_store.position);
    assert(loaded->gtid_set == to_store.gtid_set);
    std::filesystem::remove(tmp);

    // Ordered writer should emit in sequence despite out-of-order arrival
    BoundedQueue<FormattedResult> queue(8);
    std::ostringstream out;
    SqlSink sink;
    sink.stream = &out;
    OrderedWriter writer;
    std::thread writer_thread([&] { writer.consume(queue, sink); });

    queue.push(FormattedResult{2, "second\n"});
    queue.push(FormattedResult{1, "first\n"});
    queue.push(FormattedResult{3, "third\n"});
    queue.stop();

    writer_thread.join();
    assert(out.str() == "first\nsecond\nthird\n");

    return 0;
}


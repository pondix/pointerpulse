#include "replicapulse/output.h"
#include "replicapulse/threading.h"

#include <cassert>
#include <thread>
#include <vector>

using namespace replicapulse;

int main() {
    BoundedQueue<FormattedResult> queue(4);
    std::vector<std::string> received;
    SqlSink sink;
    sink.callback = [&](const std::string &sql) { received.push_back(sql); };

    OrderedWriter writer;
    std::thread t([&] { writer.consume(queue, sink); });

    queue.push(FormattedResult{2, "B"});
    queue.push(FormattedResult{1, "A"});
    queue.stop();
    t.join();

    assert(received.size() == 2);
    assert(received[0] == "A");
    assert(received[1] == "B");
    return 0;
}


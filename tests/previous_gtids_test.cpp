#include "replicapulse/parser.h"

#include <cassert>
#include <cstdint>
#include <vector>

using namespace replicapulse;

std::vector<uint8_t> build_previous_gtids_event() {
    // Build a PREVIOUS_GTIDS_EVENT with one SID and a single interval [1,4)
    std::vector<uint8_t> data(19 + 8 + 16 + 8 + 16, 0);
    auto write32 = [&](size_t offset, uint32_t v) {
        data[offset] = v & 0xff;
        data[offset + 1] = (v >> 8) & 0xff;
        data[offset + 2] = (v >> 16) & 0xff;
        data[offset + 3] = (v >> 24) & 0xff;
    };
    auto write64 = [&](size_t offset, uint64_t v) {
        for (int i = 0; i < 8; ++i) data[offset + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xff);
    };

    uint32_t event_size = data.size();
    write32(0, 1); // timestamp
    data[4] = static_cast<uint8_t>(EventType::PREVIOUS_GTIDS_EVENT);
    write32(5, 1); // server id
    write32(9, event_size);
    write32(13, event_size + 4);

    size_t p = 19;
    write64(p, 1); // SID count
    p += 8;
    for (int i = 0; i < 16; ++i) data[p + i] = static_cast<uint8_t>(i + 1); // UUID bytes
    p += 16;
    write64(p, 1); // interval count
    p += 8;
    write64(p, 1); // start
    write64(p + 8, 4); // end exclusive
    return data;
}

int main() {
    BinlogParser parser;
    BinlogEvent evt;
    auto buf = build_previous_gtids_event();
    bool ok = parser.parse_event(buf, evt);
    assert(ok);
    assert(evt.previous_gtids.has_value());
    assert(evt.previous_gtids->gtid_set.find("01020304-0506-0708-090a-0b0c0d0e0f10:1-3") != std::string::npos);
    return 0;
}


#include "replicapulse/parser.h"
#include "replicapulse/sql_formatter.h"
#include "replicapulse/checkpoint.h"

#include <cassert>
#include <cstdio>
#include <filesystem>

using namespace replicapulse;

std::vector<uint8_t> build_query_event(const std::string &schema, const std::string &query) {
    uint32_t payload_len = 4 + 4 + 1 + 2 + 2 + schema.size() + 1 + query.size();
    uint32_t event_size = 19 + payload_len;
    std::vector<uint8_t> data(event_size, 0);
    auto write32 = [&](size_t offset, uint32_t v) {
        data[offset] = v & 0xff;
        data[offset + 1] = (v >> 8) & 0xff;
        data[offset + 2] = (v >> 16) & 0xff;
        data[offset + 3] = (v >> 24) & 0xff;
    };

    write32(0, 1);                 // timestamp
    data[4] = static_cast<uint8_t>(EventType::QUERY_EVENT);
    write32(5, 1);                 // server id
    write32(9, event_size);        // event size
    write32(13, event_size + 4);   // next position
    data[17] = 0; data[18] = 0;    // flags

    size_t p = 19;
    write32(p, 99); // thread id
    p += 4;
    write32(p, 0); // exec time
    p += 4;
    data[p++] = static_cast<uint8_t>(schema.size());
    data[p++] = 0; // error code low
    data[p++] = 0; // error code high
    data[p++] = 0; // status var len low
    data[p++] = 0; // status var len high
    std::copy(schema.begin(), schema.end(), data.begin() + p);
    p += schema.size();
    data[p++] = 0; // schema null terminator
    std::copy(query.begin(), query.end(), data.begin() + p);
    return data;
}

std::vector<uint8_t> build_write_rows_event(uint64_t table_id) {
    uint32_t payload_len = 6 + 2 + 1 + 1; // table_id, flags, column-count lenenc, bitmap byte
    uint32_t event_size = 19 + payload_len;
    std::vector<uint8_t> data(event_size, 0);
    auto write32 = [&](size_t offset, uint32_t v) {
        data[offset] = v & 0xff;
        data[offset + 1] = (v >> 8) & 0xff;
        data[offset + 2] = (v >> 16) & 0xff;
        data[offset + 3] = (v >> 24) & 0xff;
    };

    write32(0, 1);
    data[4] = static_cast<uint8_t>(EventType::WRITE_ROWS_EVENT_V1);
    write32(5, 1);
    write32(9, event_size);
    write32(13, event_size + 4);
    data[17] = 0; data[18] = 0;

    size_t p = 19;
    for (int i = 0; i < 6; ++i) data[p++] = static_cast<uint8_t>((table_id >> (8 * i)) & 0xff);
    data[p++] = 0; data[p++] = 0; // flags
    data[p++] = 0x01;             // column count lenenc =1
    data[p++] = 0x01;             // included columns bitmap
    return data;
}

int main() {
    BinlogParser parser;
    BinlogEvent evt;
    auto data = build_query_event("testdb", "CREATE TABLE t(id INT)");
    bool ok = parser.parse_event(data, evt);
    assert(ok);
    assert(evt.query.has_value());

    TableMetadataCache cache;
    SqlFormatter fmt(cache);
    auto formatted = fmt.format_query(*evt.query, evt.header);
    assert(formatted.find(";") != std::string::npos);

    auto row_data = build_write_rows_event(42);
    evt = BinlogEvent{};
    ok = parser.parse_event(row_data, evt);
    assert(ok);
    assert(evt.query.has_value()); // fallback comment due to missing metadata

    // Checkpoint persistence sanity
    std::filesystem::path tmp = std::filesystem::temp_directory_path() / "replicapulse_checkpoint_test.txt";
    CheckpointManager cp(tmp.string());
    cp.store(Checkpoint{"binlog.000001", 123});
    auto loaded = cp.load();
    assert(loaded.has_value());
    assert(loaded->binlog_file == "binlog.000001");
    assert(loaded->position == 123);
    std::filesystem::remove(tmp);

    return 0;
}


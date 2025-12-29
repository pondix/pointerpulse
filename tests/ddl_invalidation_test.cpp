#include "replicapulse/parser.h"
#include "replicapulse/table_metadata.h"

#include <algorithm>
#include <cassert>
#include <vector>

using namespace replicapulse;

std::vector<uint8_t> build_ddl_query_event(const std::string &schema, const std::string &query) {
    uint32_t payload_len = 4 + 4 + 1 + 2 + 2 + schema.size() + 1 + query.size();
    uint32_t event_size = 19 + payload_len;
    std::vector<uint8_t> data(event_size, 0);
    auto write32 = [&](size_t offset, uint32_t v) {
        data[offset] = v & 0xff;
        data[offset + 1] = (v >> 8) & 0xff;
        data[offset + 2] = (v >> 16) & 0xff;
        data[offset + 3] = (v >> 24) & 0xff;
    };

    write32(0, 1); // timestamp
    data[4] = static_cast<uint8_t>(EventType::QUERY_EVENT);
    write32(5, 1); // server id
    write32(9, event_size);
    write32(13, event_size + 4);
    data[17] = 0; data[18] = 0;

    size_t p = 19;
    write32(p, 999);
    p += 4;
    write32(p, 0);
    p += 4;
    data[p++] = static_cast<uint8_t>(schema.size());
    data[p++] = 0; data[p++] = 0; // error code
    data[p++] = 0; data[p++] = 0; // status vars len
    std::copy(schema.begin(), schema.end(), data.begin() + p);
    p += schema.size();
    data[p++] = 0;
    std::copy(query.begin(), query.end(), data.begin() + p);
    return data;
}

int main() {
    TableMetadataCache cache;
    TableMetadata meta;
    meta.schema = "testdb";
    meta.name = "t";
    meta.columns = {"id"};
    meta.column_types = {ColumnType::LONG};
    meta.nullable = {false};
    cache.put(1, meta);

    BinlogParser parser;
    parser.set_table_cache(&cache);

    auto data = build_ddl_query_event("testdb", "ALTER TABLE t ADD COLUMN c INT");
    BinlogEvent evt;
    bool ok = parser.parse_event(data, evt);
    assert(ok);

    TableMetadata tmp;
    bool exists = cache.get(1, tmp);
    assert(!exists);

    // Clearing with empty table name removes everything under the schema
    cache.put(2, meta);
    cache.clear_schema("testdb", "");
    exists = cache.get(2, tmp);
    assert(!exists);
    return 0;
}

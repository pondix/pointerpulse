#include "replicapulse/parser.h"
#include "replicapulse/sql_formatter.h"
#include "replicapulse/table_metadata.h"

#include <cassert>
#include <cstdint>
#include <vector>
#include <string>
#include <iostream>

using namespace replicapulse;

static void write32(std::vector<uint8_t> &buf, size_t offset, uint32_t v) {
    buf[offset] = v & 0xff;
    buf[offset + 1] = (v >> 8) & 0xff;
    buf[offset + 2] = (v >> 16) & 0xff;
    buf[offset + 3] = (v >> 24) & 0xff;
}

std::vector<uint8_t> build_update_rows_event(uint64_t table_id) {
    const uint32_t payload_len = 6 /*table id*/ + 2 /*flags*/ + 1 /*column count*/ +
                                 1 /*before bitmap*/ + 1 /*after bitmap*/ +
                                 1 /*before nulls*/ + 4 /*before col1*/ + 2 /*len*/ + 3 /*old*/ +
                                 1 /*after nulls*/ + 4 /*after col1*/ + 2 /*len*/ + 3 /*new*/;
    const uint32_t event_size = 19 + payload_len;

    std::vector<uint8_t> data(event_size, 0);
    write32(data, 0, 1);
    data[4] = static_cast<uint8_t>(EventType::UPDATE_ROWS_EVENT_V1);
    write32(data, 5, 1);
    write32(data, 9, event_size);
    write32(data, 13, event_size + 4);
    data[17] = 0; data[18] = 0;

    size_t p = 19;
    for (int i = 0; i < 6; ++i) data[p++] = static_cast<uint8_t>((table_id >> (8 * i)) & 0xff);
    data[p++] = 0; data[p++] = 0; // flags
    data[p++] = 0x02;             // column count

    data[p++] = 0x03; // before columns bitmap (2 cols)
    data[p++] = 0x03; // after columns bitmap

    data[p++] = 0x00;                   // before null bitmap (no nulls)
    data[p++] = 10; data[p++] = 0; data[p++] = 0; data[p++] = 0; // before col1 (LONG)
    data[p++] = 0x03; data[p++] = 0x00; // before col2 length
    data[p++] = 'o'; data[p++] = 'l'; data[p++] = 'd';

    data[p++] = 0x00;                   // after null bitmap
    data[p++] = 11; data[p++] = 0; data[p++] = 0; data[p++] = 0; // after col1
    data[p++] = 0x03; data[p++] = 0x00; // after col2 length
    data[p++] = 'n'; data[p++] = 'e'; data[p++] = 'w';

    return data;
}

int main() {
    TableMetadataCache cache;
    TableMetadata meta;
    meta.schema = "test";
    meta.name = "items";
    meta.columns = {"id", "label"};
    meta.column_types = {ColumnType::LONG, ColumnType::VAR_STRING};
    meta.metadata = {0, 256};  // 256 means 2-byte length prefix for VAR_STRING
    meta.nullable = {false, false};
    meta.primary_key = {true, false};
    meta.unique_key = {true, false};
    cache.put(1, meta);

    BinlogParser parser;
    parser.set_table_cache(&cache);
    BinlogEvent evt;
    auto bytes = build_update_rows_event(1);
    bool ok = parser.parse_event(bytes, evt);
    assert(ok);
    assert(evt.rows.has_value());
    const auto &row_evt = *evt.rows;
    assert(row_evt.is_update);
    assert(row_evt.rows.size() == 1);
    const auto &change = row_evt.rows[0];
    assert(change.before.size() == 2);
    assert(change.after.size() == 2);
    assert(change.before[0].as_string == "10");
    assert(change.after[0].as_string == "11");
    assert(change.before[1].as_string == "old");
    assert(change.after[1].as_string == "new");

    SqlFormatter fmt(cache);
    auto sql = fmt.format_rows_event(row_evt, evt.header);
    assert(sql.find("UPDATE `test`.`items`") != std::string::npos);
    assert(sql.find("`id` = 10") != std::string::npos);
    assert(sql.find("`label` = 'new'") != std::string::npos);

    std::cout << "update_rows_decode_test passed\n";
    return 0;
}


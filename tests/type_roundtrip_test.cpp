#include "replicapulse/sql_formatter.h"
#include "replicapulse/table_metadata.h"

#include <cassert>
#include <iostream>

using namespace replicapulse;

int main() {
    TableMetadataCache cache;
    TableMetadata meta;
    meta.schema = "testdb";
    meta.name = "times";
    meta.columns = {"price", "ts", "dt", "tm", "bits"};
    meta.column_types = {ColumnType::NEWDECIMAL, ColumnType::DATETIME2, ColumnType::DATE, ColumnType::TIME2, ColumnType::BIT};
    meta.metadata = {static_cast<uint16_t>((6 << 8) | 2), 0, 0, 6, 16};
    meta.nullable = {false, false, false, false, false};
    meta.primary_key = {true, false, false, false, false};
    meta.unique_key = meta.primary_key;
    cache.put(2, meta);

    RowsEvent rows;
    rows.table_id = 2;
    RowChange change;

    CellValue price{false, true, ColumnType::NEWDECIMAL, {}, "1234.56"};
    CellValue ts{false, true, ColumnType::DATETIME2, {}, "2024-01-02 03:04:05"};
    CellValue dt{false, true, ColumnType::DATE, {}, "2024-01-02"};
    CellValue tm{false, true, ColumnType::TIME2, {}, "10:11:12.123000"};
    CellValue bits{false, true, ColumnType::BIT, {}, "42"};
    change.after = {price, ts, dt, tm, bits};
    rows.rows.push_back(change);

    SqlFormatter fmt(cache);
    auto sql = fmt.format_rows_event(rows, BinlogEventHeader{});
    assert(sql.find("1234.56") != std::string::npos);
    assert(sql.find("2024-01-02 03:04:05") != std::string::npos);
    assert(sql.find("2024-01-02") != std::string::npos);
    assert(sql.find("10:11:12.123000") != std::string::npos);
    assert(sql.find("42") != std::string::npos);

    std::cout << "type_roundtrip_test passed\n";
    return 0;
}

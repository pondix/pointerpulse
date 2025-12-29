#include "replicapulse/sql_formatter.h"
#include "replicapulse/table_metadata.h"

#include <cassert>
#include <iostream>

using namespace replicapulse;

int main() {
    TableMetadataCache cache;
    TableMetadata meta;
    meta.schema = "testdb";
    meta.name = "widgets";
    meta.columns = {"id", "name", "payload"};
    meta.column_types = {ColumnType::LONG, ColumnType::VAR_STRING, ColumnType::BLOB};
    meta.metadata = {0, 255, 0};
    meta.nullable = {false, false, true};
    meta.primary_key = {true, false, false};
    meta.unique_key = {true, false, false};
    cache.put(1, meta);

    RowsEvent rows;
    rows.table_id = 1;
    rows.is_update = false;
    rows.is_delete = false;
    RowChange change;
    CellValue id; id.present = true; id.is_null = false; id.type = ColumnType::LONG; id.as_string = "42";
    CellValue name; name.present = true; name.is_null = false; name.type = ColumnType::VAR_STRING; name.as_string = "Widget's";
    CellValue payload; payload.present = true; payload.is_null = false; payload.type = ColumnType::BLOB; payload.raw = {0xde,0xad};
    change.after = {id, name, payload};
    rows.rows.push_back(change);

    SqlFormatter fmt(cache);
    BinlogEventHeader header;
    header.binlog_file = "mysql-bin.000001";
    header.start_position = 1234;
    auto sql = fmt.format_event_prefix(header) + fmt.format_rows_event(rows, header);
    assert(sql.find("INSERT INTO `testdb`.`widgets`") != std::string::npos);
    assert(sql.find("Widget\\'s") != std::string::npos);
    assert(sql.find("0xdead") != std::string::npos);

    SqlFormatter no_coords(cache, true, false);
    auto no_prefix_sql = no_coords.format_event_prefix(header) + no_coords.format_rows_event(rows, header);
    assert(no_prefix_sql.find("binlog") == std::string::npos);

    SqlFormatter no_gtid(cache, false, false);
    GtidEvent g{"uuid:1"};
    assert(no_gtid.format_gtid(g).empty());

    std::cout << "sql_formatter_test passed\n";
    return 0;
}

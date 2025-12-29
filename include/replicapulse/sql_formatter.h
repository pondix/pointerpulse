#pragma once

#include "event.h"
#include "table_metadata.h"

#include <ostream>
#include <string>
#include <vector>

namespace replicapulse {

class SqlFormatter {
public:
    SqlFormatter(const TableMetadataCache &cache, bool include_gtid = true, bool include_coords = true)
        : cache_(cache), include_gtid_(include_gtid), include_coords_(include_coords) {}

    std::string format_query(const QueryEvent &event, const BinlogEventHeader &header) const;
    std::string format_rows_event(const RowsEvent &rows, const BinlogEventHeader &header) const;
    std::string format_gtid(const GtidEvent &gtid) const;
    std::string format_begin(const BinlogEventHeader &header) const;
    std::string format_commit(const BinlogEventHeader &header) const;
    std::string format_event_prefix(const BinlogEventHeader &header) const;
    std::string escape_identifier(const std::string &ident) const;
    std::string escape_value(const CellValue &value, const ColumnType type) const;

private:
    const TableMetadataCache &cache_;
    bool include_gtid_{true};
    bool include_coords_{true};
    std::string format_insert(const RowsEvent &rows, const TableMetadata &meta) const;
    std::string format_delete(const RowsEvent &rows, const TableMetadata &meta) const;
    std::string format_update(const RowsEvent &rows, const TableMetadata &meta) const;
    std::string build_predicate(const RowChange &change, const TableMetadata &meta) const;
};

} // namespace replicapulse

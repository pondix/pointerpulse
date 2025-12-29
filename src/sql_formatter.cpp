#include "replicapulse/sql_formatter.h"

#include <iomanip>
#include <sstream>

namespace replicapulse {
namespace {
std::string hex_encode(const std::vector<uint8_t> &data) {
    std::ostringstream oss;
    oss << "0x";
    for (auto b : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}
}

std::string SqlFormatter::escape_identifier(const std::string &ident) const {
    std::string out = "`";
    for (char c : ident) {
        if (c == '`') out.push_back('`');
        out.push_back(c);
    }
    out.push_back('`');
    return out;
}

std::string SqlFormatter::escape_value(const CellValue &value, const ColumnType type) const {
    if (!value.present) return "DEFAULT";
    if (value.is_null) return "NULL";
    switch (type) {
    case ColumnType::TINY:
    case ColumnType::SHORT:
    case ColumnType::LONG:
    case ColumnType::INT24:
    case ColumnType::LONGLONG:
    case ColumnType::FLOAT:
    case ColumnType::DOUBLE:
    case ColumnType::NEWDECIMAL:
    case ColumnType::BIT:
    case ColumnType::YEAR:
        return value.as_string;
    case ColumnType::BLOB:
    case ColumnType::TINY_BLOB:
    case ColumnType::MEDIUM_BLOB:
    case ColumnType::LONG_BLOB:
    case ColumnType::GEOMETRY:
        return hex_encode(value.raw);
    default: {
        std::string escaped = "'";
        for (unsigned char c : value.as_string) {
            switch (c) {
            case '\\': escaped += "\\\\"; break;
            case '\'': escaped += "\\'"; break;
            case '"': escaped += "\\\""; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                escaped.push_back(static_cast<char>(c));
            }
        }
        escaped.push_back('\'');
        return escaped;
    }
    }
}

std::string SqlFormatter::format_event_prefix(const BinlogEventHeader &header) const {
    if (!include_coords_ || header.binlog_file.empty()) return "";
    std::ostringstream oss;
    oss << "/* binlog " << header.binlog_file << ":" << header.start_position << " */\n";
    return oss.str();
}

std::string SqlFormatter::format_query(const QueryEvent &event, const BinlogEventHeader &header) const {
    std::string q = event.query;
    if (!q.empty() && q.back() != ';') q.push_back(';');
    q.push_back('\n');
    return q;
}

std::string SqlFormatter::format_gtid(const GtidEvent &gtid) const {
    if (!include_gtid_) return "";
    return "/* GTID " + gtid.gtid + " */\n";
}

std::string SqlFormatter::format_begin(const BinlogEventHeader &) const { return "BEGIN;\n"; }

std::string SqlFormatter::format_commit(const BinlogEventHeader &) const { return "COMMIT;\n"; }

std::string SqlFormatter::format_insert(const RowsEvent &rows, const TableMetadata &meta) const {
    std::ostringstream oss;
    for (const auto &change : rows.rows) {
        oss << "INSERT INTO " << escape_identifier(meta.schema) << "." << escape_identifier(meta.name) << " (";
        bool first = true;
        for (size_t i = 0; i < meta.columns.size(); ++i) {
            if (!change.after.empty() && change.after[i].present) {
                if (!first) oss << ", ";
                first = false;
                oss << escape_identifier(meta.columns[i]);
            }
        }
        oss << ") VALUES (";
        first = true;
        for (size_t i = 0; i < meta.columns.size(); ++i) {
            if (!change.after.empty() && change.after[i].present) {
                if (!first) oss << ", ";
                first = false;
                oss << escape_value(change.after[i], meta.column_types[i]);
            }
        }
        oss << ");\n";
    }
    return oss.str();
}

std::string SqlFormatter::build_predicate(const RowChange &change, const TableMetadata &meta) const {
    std::ostringstream oss;
    bool first = true;
    auto emit_col = [&](size_t idx) {
        if (!change.before[idx].present) return;
        if (!first) oss << " AND ";
        first = false;
        oss << escape_identifier(meta.columns[idx]) << " = " << escape_value(change.before[idx], meta.column_types[idx]);
    };

    for (size_t i = 0; i < meta.columns.size(); ++i) {
        if (meta.primary_key.size() > i && meta.primary_key[i]) emit_col(i);
    }
    if (first) {
        for (size_t i = 0; i < meta.columns.size(); ++i) {
            if (meta.unique_key.size() > i && meta.unique_key[i]) emit_col(i);
        }
    }
    if (first) {
        for (size_t i = 0; i < meta.columns.size(); ++i) emit_col(i);
    }
    return oss.str();
}

std::string SqlFormatter::format_delete(const RowsEvent &rows, const TableMetadata &meta) const {
    std::ostringstream oss;
    for (const auto &change : rows.rows) {
        oss << "DELETE FROM " << escape_identifier(meta.schema) << "." << escape_identifier(meta.name) << " WHERE "
            << build_predicate(change, meta) << ";\n";
    }
    return oss.str();
}

std::string SqlFormatter::format_update(const RowsEvent &rows, const TableMetadata &meta) const {
    std::ostringstream oss;
    for (const auto &change : rows.rows) {
        oss << "UPDATE " << escape_identifier(meta.schema) << "." << escape_identifier(meta.name) << " SET ";
        bool first = true;
        for (size_t i = 0; i < meta.columns.size(); ++i) {
            if (!change.after.empty() && change.after[i].present) {
                if (!first) oss << ", ";
                first = false;
                oss << escape_identifier(meta.columns[i]) << " = " << escape_value(change.after[i], meta.column_types[i]);
            }
        }
        oss << " WHERE " << build_predicate(change, meta) << ";\n";
    }
    return oss.str();
}

std::string SqlFormatter::format_rows_event(const RowsEvent &rows, const BinlogEventHeader &header) const {
    TableMetadata meta;
    if (!cache_.get(rows.table_id, meta)) return "";
    if (rows.is_delete) return format_delete(rows, meta);
    if (rows.is_update) return format_update(rows, meta);
    return format_insert(rows, meta);
}

} // namespace replicapulse

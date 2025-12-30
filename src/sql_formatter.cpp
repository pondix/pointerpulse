#include "replicapulse/sql_formatter.h"

#include <iomanip>
#include <sstream>

namespace replicapulse {
namespace {

// Thread-local buffer for building SQL strings to reduce allocations
thread_local std::string g_sql_buffer;

std::string hex_encode(const std::vector<uint8_t> &data) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2 + 2);
    result += "0x";
    for (auto b : data) {
        result.push_back(hex_chars[(b >> 4) & 0x0F]);
        result.push_back(hex_chars[b & 0x0F]);
    }
    return result;
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
    g_sql_buffer.clear();
    g_sql_buffer += "/* binlog ";
    g_sql_buffer += header.binlog_file;
    g_sql_buffer += ":";
    g_sql_buffer += std::to_string(header.start_position);
    g_sql_buffer += " */\n";
    return g_sql_buffer;
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
    g_sql_buffer.clear();
    g_sql_buffer.reserve(4096);  // Reserve reasonable default size
    for (const auto &change : rows.rows) {
        g_sql_buffer += "INSERT INTO ";
        g_sql_buffer += escape_identifier(meta.schema);
        g_sql_buffer += ".";
        g_sql_buffer += escape_identifier(meta.name);
        g_sql_buffer += " (";
        bool first = true;
        for (size_t i = 0; i < meta.columns.size(); ++i) {
            if (!change.after.empty() && change.after[i].present) {
                if (!first) g_sql_buffer += ", ";
                first = false;
                g_sql_buffer += escape_identifier(meta.columns[i]);
            }
        }
        g_sql_buffer += ") VALUES (";
        first = true;
        for (size_t i = 0; i < meta.columns.size(); ++i) {
            if (!change.after.empty() && change.after[i].present) {
                if (!first) g_sql_buffer += ", ";
                first = false;
                g_sql_buffer += escape_value(change.after[i], meta.column_types[i]);
            }
        }
        g_sql_buffer += ");\n";
    }
    return g_sql_buffer;
}

std::string SqlFormatter::build_predicate(const RowChange &change, const TableMetadata &meta) const {
    thread_local std::string predicate_buffer;
    predicate_buffer.clear();
    predicate_buffer.reserve(512);
    bool first = true;
    auto emit_col = [&](size_t idx) {
        if (!change.before[idx].present) return;
        if (!first) predicate_buffer += " AND ";
        first = false;
        predicate_buffer += escape_identifier(meta.columns[idx]);
        predicate_buffer += " = ";
        predicate_buffer += escape_value(change.before[idx], meta.column_types[idx]);
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
    return predicate_buffer;
}

std::string SqlFormatter::format_delete(const RowsEvent &rows, const TableMetadata &meta) const {
    g_sql_buffer.clear();
    g_sql_buffer.reserve(2048);
    for (const auto &change : rows.rows) {
        g_sql_buffer += "DELETE FROM ";
        g_sql_buffer += escape_identifier(meta.schema);
        g_sql_buffer += ".";
        g_sql_buffer += escape_identifier(meta.name);
        g_sql_buffer += " WHERE ";
        g_sql_buffer += build_predicate(change, meta);
        g_sql_buffer += ";\n";
    }
    return g_sql_buffer;
}

std::string SqlFormatter::format_update(const RowsEvent &rows, const TableMetadata &meta) const {
    g_sql_buffer.clear();
    g_sql_buffer.reserve(4096);
    for (const auto &change : rows.rows) {
        g_sql_buffer += "UPDATE ";
        g_sql_buffer += escape_identifier(meta.schema);
        g_sql_buffer += ".";
        g_sql_buffer += escape_identifier(meta.name);
        g_sql_buffer += " SET ";
        bool first = true;
        for (size_t i = 0; i < meta.columns.size(); ++i) {
            if (!change.after.empty() && change.after[i].present) {
                if (!first) g_sql_buffer += ", ";
                first = false;
                g_sql_buffer += escape_identifier(meta.columns[i]);
                g_sql_buffer += " = ";
                g_sql_buffer += escape_value(change.after[i], meta.column_types[i]);
            }
        }
        g_sql_buffer += " WHERE ";
        g_sql_buffer += build_predicate(change, meta);
        g_sql_buffer += ";\n";
    }
    return g_sql_buffer;
}

std::string SqlFormatter::format_rows_event(const RowsEvent &rows, const BinlogEventHeader &header) const {
    TableMetadata meta;
    if (!cache_.get(rows.table_id, meta)) return "";
    if (rows.is_delete) return format_delete(rows, meta);
    if (rows.is_update) return format_update(rows, meta);
    return format_insert(rows, meta);
}

} // namespace replicapulse

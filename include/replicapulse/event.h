#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <unordered_map>

namespace replicapulse {

enum class EventType : uint8_t {
    UNKNOWN = 0,
    START_EVENT_V3 = 1,
    QUERY_EVENT = 2,
    STOP_EVENT = 3,
    ROTATE_EVENT = 4,
    FORMAT_DESCRIPTION_EVENT = 15,
    TABLE_MAP_EVENT = 19,
    WRITE_ROWS_EVENT_V1 = 23,
    UPDATE_ROWS_EVENT_V1 = 24,
    DELETE_ROWS_EVENT_V1 = 25,
    WRITE_ROWS_EVENT_V2 = 30,
    UPDATE_ROWS_EVENT_V2 = 31,
    DELETE_ROWS_EVENT_V2 = 32,
    GTID_EVENT = 33,
    HEARTBEAT_LOG_EVENT = 27,
    ANONYMOUS_GTID_EVENT = 40,
    PREVIOUS_GTIDS_EVENT = 35,
    XID_EVENT = 16,
};

enum class ColumnType : uint8_t {
    DECIMAL = 0x00,
    TINY = 0x01,
    SHORT = 0x02,
    LONG = 0x03,
    FLOAT = 0x04,
    DOUBLE = 0x05,
    NULL_TYPE = 0x06,
    TIMESTAMP = 0x07,
    LONGLONG = 0x08,
    INT24 = 0x09,
    DATE = 0x0a,
    TIME = 0x0b,
    DATETIME = 0x0c,
    YEAR = 0x0d,
    VARCHAR = 0x0f,
    BIT = 0x10,
    TIMESTAMP2 = 0x11,
    DATETIME2 = 0x12,
    TIME2 = 0x13,
    JSON = 0xf5,
    NEWDECIMAL = 0xf6,
    ENUM = 0xf7,
    SET = 0xf8,
    TINY_BLOB = 0xf9,
    MEDIUM_BLOB = 0xfa,
    LONG_BLOB = 0xfb,
    BLOB = 0xfc,
    VAR_STRING = 0xfd,
    STRING = 0xfe,
    GEOMETRY = 0xff
};

struct BinlogEventHeader {
    uint32_t timestamp{0};
    EventType type{EventType::UNKNOWN};
    uint32_t server_id{0};
    uint32_t event_size{0};
    uint32_t next_position{0};
    uint16_t flags{0};
    std::string binlog_file;
    uint32_t start_position{0};
};

enum class ChecksumAlgorithm : uint8_t {
    OFF = 0xFF,
    CRC32 = 0x01,
};

struct FormatDescriptionEvent {
    uint16_t binlog_version{0};
    std::string server_version;
    uint32_t create_timestamp{0};
    uint8_t header_length{19};
    std::vector<uint8_t> type_header_lengths;
    ChecksumAlgorithm checksum{ChecksumAlgorithm::OFF};
};

struct QueryEvent {
    std::string schema;
    std::string query;
};

struct RotateEvent {
    uint64_t position{4};
    std::string next_binlog;
};

struct TableMapEvent {
    uint64_t table_id{0};
    std::string schema;
    std::string table;
    std::vector<ColumnType> column_types;
    std::vector<uint16_t> metadata;
    std::vector<bool> null_bitmap;
};

struct CellValue {
    bool is_null{false};
    bool present{false};
    ColumnType type{ColumnType::NULL_TYPE};
    std::vector<uint8_t> raw;
    std::string as_string;
};

struct RowChange {
    std::vector<CellValue> before;
    std::vector<CellValue> after;
};

struct RowsEvent {
    uint64_t table_id{0};
    bool is_update{false};
    bool is_delete{false};
    std::vector<bool> included_columns_before;
    std::vector<bool> included_columns_after;
    std::vector<RowChange> rows;
};

struct XidEvent {
    uint64_t xid{0};
};

struct GtidEvent {
    std::string gtid;
};

struct PreviousGtidsEvent {
    std::string gtid_set;
};

struct BinlogEvent {
    uint64_t seq_no{0};
    BinlogEventHeader header;
    std::optional<FormatDescriptionEvent> format_desc;
    std::optional<QueryEvent> query;
    std::optional<RotateEvent> rotate;
    std::optional<TableMapEvent> table_map;
    std::optional<RowsEvent> rows;
    std::optional<XidEvent> xid;
    std::optional<GtidEvent> gtid;
    std::optional<PreviousGtidsEvent> previous_gtids;
};

} // namespace replicapulse

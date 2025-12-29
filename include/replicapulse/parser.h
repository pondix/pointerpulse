#pragma once

#include "event.h"
#include "table_metadata.h"

#include <cstddef>
#include <cstdint>
#include <vector>
#include <optional>

namespace replicapulse {

class BinlogParser {
public:
    BinlogParser() = default;
    bool parse_event(const std::vector<uint8_t> &data, BinlogEvent &event);
    void set_table_cache(TableMetadataCache *cache) { cache_ = cache; }

private:
    TableMetadataCache *cache_{nullptr};
    BinlogEventHeader parse_header(const std::vector<uint8_t> &data);
    bool parse_format_description(const std::vector<uint8_t> &data, BinlogEvent &event);
    bool parse_query_event(const std::vector<uint8_t> &data, BinlogEvent &event);
    bool parse_rotate_event(const std::vector<uint8_t> &data, BinlogEvent &event);
    bool parse_table_map_event(const std::vector<uint8_t> &data, BinlogEvent &event);
    bool parse_rows_event(const std::vector<uint8_t> &data, BinlogEvent &event, bool is_update, bool is_delete);
    bool parse_xid_event(const std::vector<uint8_t> &data, BinlogEvent &event);
    bool parse_gtid_event(const std::vector<uint8_t> &data, BinlogEvent &event);
    bool parse_previous_gtids_event(const std::vector<uint8_t> &data, BinlogEvent &event);

    bool checksum_enabled_{false};
};

} // namespace replicapulse

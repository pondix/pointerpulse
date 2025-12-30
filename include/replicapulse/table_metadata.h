#pragma once

#include "event.h"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <shared_mutex>

namespace replicapulse {

struct TableMetadata {
    std::string schema;
    std::string name;
    std::vector<std::string> columns;
    std::vector<ColumnType> column_types;
    std::vector<uint16_t> metadata;
    std::vector<bool> nullable;
    std::vector<bool> primary_key;
    std::vector<bool> unique_key;
};

class TableMetadataCache {
public:
    void put(uint64_t table_id, TableMetadata meta);
    bool get(uint64_t table_id, TableMetadata &meta) const;
    void clear_schema(const std::string &schema, const std::string &table);
private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<uint64_t, TableMetadata> by_id_;
};

} // namespace replicapulse

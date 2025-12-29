#include "replicapulse/table_metadata.h"

namespace replicapulse {

void TableMetadataCache::put(uint64_t table_id, TableMetadata meta) {
    std::lock_guard<std::mutex> lock(mutex_);
    by_id_[table_id] = std::move(meta);
}

bool TableMetadataCache::get(uint64_t table_id, TableMetadata &meta) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = by_id_.find(table_id);
    if (it == by_id_.end()) return false;
    meta = it->second;
    return true;
}

void TableMetadataCache::clear_schema(const std::string &schema, const std::string &table) {
    if (schema.empty()) return;
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = by_id_.begin(); it != by_id_.end();) {
        bool schema_match = it->second.schema == schema;
        bool table_match = table.empty() || it->second.name == table;
        if (schema_match && table_match) {
            it = by_id_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace replicapulse

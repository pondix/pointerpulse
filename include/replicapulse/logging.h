#pragma once

#include <atomic>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>

namespace replicapulse {

// Log levels (can be combined as bitmask)
enum class LogLevel : uint32_t {
    NONE    = 0,
    ERROR   = 1 << 0,  // Always show errors
    WARN    = 1 << 1,  // Warnings
    INFO    = 1 << 2,  // Basic operational info
    DEBUG   = 1 << 3,  // Detailed debug info
    TRACE   = 1 << 4,  // Very verbose tracing
    ALL     = 0xFFFFFFFF
};

// Log categories (can be combined as bitmask)
enum class LogCategory : uint32_t {
    NONE       = 0,
    SERVICE    = 1 << 0,   // Service lifecycle, threads
    CONNECTION = 1 << 1,   // Socket operations
    HANDSHAKE  = 1 << 2,   // MySQL handshake/auth
    BINLOG     = 1 << 3,   // Binlog streaming
    PARSER     = 1 << 4,   // Event parsing
    QUERY      = 1 << 5,   // SQL queries
    OUTPUT     = 1 << 6,   // Output/formatting
    CHECKPOINT = 1 << 7,   // Checkpointing
    ALL        = 0xFFFFFFFF
};

inline LogLevel operator|(LogLevel a, LogLevel b) {
    return static_cast<LogLevel>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline LogLevel operator&(LogLevel a, LogLevel b) {
    return static_cast<LogLevel>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline LogCategory operator|(LogCategory a, LogCategory b) {
    return static_cast<LogCategory>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline LogCategory operator&(LogCategory a, LogCategory b) {
    return static_cast<LogCategory>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

class Logger {
public:
    static Logger& instance() {
        static Logger logger;
        return logger;
    }

    void set_level(LogLevel level) { level_ = level; }
    void set_categories(LogCategory cats) { categories_ = cats; }

    void enable_level(LogLevel level) {
        level_ = level_ | level;
    }

    void enable_category(LogCategory cat) {
        categories_ = categories_ | cat;
    }

    LogLevel level() const { return level_; }
    LogCategory categories() const { return categories_; }

    bool should_log(LogLevel level, LogCategory cat) const {
        return (static_cast<uint32_t>(level_) & static_cast<uint32_t>(level)) != 0 &&
               (static_cast<uint32_t>(categories_) & static_cast<uint32_t>(cat)) != 0;
    }

    static const char* level_str(LogLevel level) {
        switch (level) {
            case LogLevel::ERROR: return "ERROR";
            case LogLevel::WARN:  return "WARN ";
            case LogLevel::INFO:  return "INFO ";
            case LogLevel::DEBUG: return "DEBUG";
            case LogLevel::TRACE: return "TRACE";
            default: return "?????";
        }
    }

    static const char* category_str(LogCategory cat) {
        switch (cat) {
            case LogCategory::SERVICE:    return "SERVICE   ";
            case LogCategory::CONNECTION: return "CONNECTION";
            case LogCategory::HANDSHAKE:  return "HANDSHAKE ";
            case LogCategory::BINLOG:     return "BINLOG    ";
            case LogCategory::PARSER:     return "PARSER    ";
            case LogCategory::QUERY:      return "QUERY     ";
            case LogCategory::OUTPUT:     return "OUTPUT    ";
            case LogCategory::CHECKPOINT: return "CHECKPOINT";
            default: return "??????????";
        }
    }

private:
    Logger() : level_(LogLevel::ERROR | LogLevel::WARN | LogLevel::INFO),
               categories_(LogCategory::ALL) {}

    LogLevel level_;
    LogCategory categories_;
};

// Helper class for streaming log messages
class LogStream {
public:
    LogStream(LogLevel level, LogCategory cat, bool enabled)
        : enabled_(enabled), level_(level), cat_(cat) {}

    ~LogStream() {
        if (enabled_) {
            std::cerr << "[" << Logger::level_str(level_) << "] "
                      << "[" << Logger::category_str(cat_) << "] "
                      << ss_.str() << std::endl;
        }
    }

    template<typename T>
    LogStream& operator<<(const T& value) {
        if (enabled_) {
            ss_ << value;
        }
        return *this;
    }

private:
    bool enabled_;
    LogLevel level_;
    LogCategory cat_;
    std::ostringstream ss_;
};

// Macros for zero-overhead logging when disabled
#define LOG(level, cat) \
    if (!replicapulse::Logger::instance().should_log(level, cat)) {} \
    else replicapulse::LogStream(level, cat, true)

#define LOG_ERROR(cat)   LOG(replicapulse::LogLevel::ERROR, cat)
#define LOG_WARN(cat)    LOG(replicapulse::LogLevel::WARN, cat)
#define LOG_INFO(cat)    LOG(replicapulse::LogLevel::INFO, cat)
#define LOG_DEBUG(cat)   LOG(replicapulse::LogLevel::DEBUG, cat)
#define LOG_TRACE(cat)   LOG(replicapulse::LogLevel::TRACE, cat)

// Hex dump helper
inline void log_hex(LogLevel level, LogCategory cat, const std::string& label,
                    const uint8_t* data, size_t len, size_t max_len = 64) {
    if (!Logger::instance().should_log(level, cat)) return;

    std::ostringstream ss;
    ss << label << " (" << len << " bytes): ";
    for (size_t i = 0; i < len && i < max_len; ++i) {
        char hex[4];
        snprintf(hex, sizeof(hex), "%02x ", data[i]);
        ss << hex;
    }
    if (len > max_len) ss << "...";

    std::cerr << "[" << Logger::level_str(level) << "] "
              << "[" << Logger::category_str(cat) << "] "
              << ss.str() << std::endl;
}

} // namespace replicapulse

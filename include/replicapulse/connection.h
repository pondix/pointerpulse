#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <optional>
#include <mutex>
#include <condition_variable>
#include <openssl/ssl.h>

namespace replicapulse {

struct Packet {
    std::vector<uint8_t> payload;
    uint8_t sequence{0};
};

struct BinlogPacket {
    std::vector<uint8_t> event_data;
};

class MySQLConnection {
public:
    MySQLConnection() = default;
    ~MySQLConnection();

    bool connect(const std::string &host, uint16_t port, const std::string &user,
                 const std::string &password, uint32_t server_id,
                 const std::string &binlog_file, uint32_t position);

    bool connect_gtid(const std::string &host, uint16_t port, const std::string &user,
                      const std::string &password, uint32_t server_id,
                      const std::string &binlog_file, uint64_t position,
                      const std::string &gtid_set);

    bool connect_sql(const std::string &host, uint16_t port, const std::string &user,
                     const std::string &password);

    bool send_query(const std::string &query, std::vector<std::vector<std::string>> &rows);

    bool read_binlog_packet(BinlogPacket &packet);

    bool is_connected() const { return sock_fd_ >= 0; }
    void close();
    bool set_timeout_ms(uint32_t timeout_ms);
    void set_default_timeout_ms(uint32_t timeout_ms) { timeout_ms_ = timeout_ms; }
    void set_use_tls(bool use_tls) { use_tls_ = use_tls; }
    void set_debug(bool debug) { debug_ = debug; }

private:
    int sock_fd_{-1};
    bool use_tls_{false};
    bool ssl_active_{false};
    SSL_CTX *ssl_ctx_{nullptr};
    SSL *ssl_handle_{nullptr};
    uint8_t sequence_{0};
    std::vector<uint8_t> scramble_buffer_;
    uint32_t timeout_ms_{1000};
    bool debug_{false};

    bool read_packet(Packet &packet);
    bool write_packet(const std::vector<uint8_t> &payload);
    bool open_socket(const std::string &host, uint16_t port);
    bool handshake(const std::string &host, const std::string &user, const std::string &password);
    bool ensure_tls(const std::string &host, uint32_t capability_flags);
    bool recv_all(uint8_t *buf, size_t len);
    bool send_all(const uint8_t *buf, size_t len);
    bool request_binlog_stream(uint32_t server_id, const std::string &binlog_file, uint32_t position);
    bool request_binlog_stream_gtid(uint32_t server_id, const std::string &binlog_file, uint64_t position,
                                    const std::string &gtid_set);
    bool send_command(uint8_t command, const std::vector<uint8_t> &data);

    uint32_t capability_flags_{0};
};

} // namespace replicapulse

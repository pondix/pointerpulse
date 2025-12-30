#include "replicapulse/connection.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <string>

namespace replicapulse {

namespace {
constexpr uint32_t CLIENT_LONG_PASSWORD = 1u << 0;
constexpr uint32_t CLIENT_LONG_FLAG = 1u << 2;
constexpr uint32_t CLIENT_CONNECT_WITH_DB = 1u << 3;
constexpr uint32_t CLIENT_PROTOCOL_41 = 1u << 9;
constexpr uint32_t CLIENT_SECURE_CONNECTION = 1u << 15;
constexpr uint32_t CLIENT_MULTI_RESULTS = 1u << 17;
constexpr uint32_t CLIENT_PLUGIN_AUTH = 1u << 19;
constexpr uint32_t CLIENT_DEPRECATE_EOF = 1u << 24;
constexpr uint32_t CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 1u << 21;
constexpr uint32_t CLIENT_SSL = 1u << 11;
constexpr uint8_t COM_QUERY = 0x03;
constexpr uint8_t COM_BINLOG_DUMP = 0x12;
constexpr uint8_t COM_BINLOG_DUMP_GTID = 0x1e;

uint32_t read_uint3(const uint8_t *ptr) { return ptr[0] | (ptr[1] << 8) | (ptr[2] << 16); }
uint16_t read_uint2(const uint8_t *ptr) { return ptr[0] | (ptr[1] << 8); }
uint64_t read_uint6(const uint8_t *ptr) {
    uint64_t v = 0;
    for (int i = 0; i < 6; ++i) v |= (static_cast<uint64_t>(ptr[i]) << (8 * i));
    return v;
}

std::vector<uint8_t> scramble_native_password(const std::string &password, const std::vector<uint8_t> &salt) {
    std::vector<uint8_t> stage1(SHA_DIGEST_LENGTH);
    SHA1(reinterpret_cast<const unsigned char *>(password.data()), password.size(), stage1.data());

    std::vector<uint8_t> stage2(SHA_DIGEST_LENGTH);
    SHA1(stage1.data(), stage1.size(), stage2.data());

    std::vector<uint8_t> combined;
    combined.reserve(salt.size() + stage2.size());
    combined.insert(combined.end(), salt.begin(), salt.end());
    combined.insert(combined.end(), stage2.begin(), stage2.end());

    std::vector<uint8_t> stage3(SHA_DIGEST_LENGTH);
    SHA1(combined.data(), combined.size(), stage3.data());

    std::vector<uint8_t> token(SHA_DIGEST_LENGTH);
    for (size_t i = 0; i < token.size(); ++i) {
        token[i] = stage1[i] ^ stage3[i];
    }
    return token;
}

std::vector<uint8_t> scramble_caching_sha2_password(const std::string &password, const std::vector<uint8_t> &salt) {
    std::vector<uint8_t> stage1(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char *>(password.data()), password.size(), stage1.data());

    std::vector<uint8_t> stage2(SHA256_DIGEST_LENGTH);
    SHA256(stage1.data(), stage1.size(), stage2.data());

    std::vector<uint8_t> combined;
    combined.reserve(salt.size() + stage2.size());
    combined.insert(combined.end(), salt.begin(), salt.end());
    combined.insert(combined.end(), stage2.begin(), stage2.end());

    std::vector<uint8_t> stage3(SHA256_DIGEST_LENGTH);
    SHA256(combined.data(), combined.size(), stage3.data());

    std::vector<uint8_t> token(stage1.size());
    for (size_t i = 0; i < token.size(); ++i) {
        token[i] = stage1[i] ^ stage3[i];
    }
    return token;
}

uint64_t read_lenenc_int(const uint8_t *&p, const uint8_t *end) {
    if (p >= end) return 0;
    uint8_t first = *p++;
    if (first < 0xfb) return first;
    if (first == 0xfc && p + 2 <= end) {
        uint64_t v = p[0] | (p[1] << 8);
        p += 2;
        return v;
    }
    if (first == 0xfd && p + 3 <= end) {
        uint64_t v = p[0] | (p[1] << 8) | (p[2] << 16);
        p += 3;
        return v;
    }
    if (first == 0xfe && p + 8 <= end) {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= (static_cast<uint64_t>(p[i]) << (8 * i));
        p += 8;
        return v;
    }
    return 0;
}

std::string read_lenenc_string(const uint8_t *&p, const uint8_t *end) {
    uint64_t len = read_lenenc_int(p, end);
    if (p + len > end) len = end - p;
    std::string s(reinterpret_cast<const char *>(p), len);
    p += len;
    return s;
}

bool is_eof_packet(const Packet &packet) {
    if (packet.payload.size() < 5) return false;
    return packet.payload[0] == 0xfe && packet.payload.size() < 9;
}

} // namespace

MySQLConnection::~MySQLConnection() { close(); }

void MySQLConnection::close() {
    if (ssl_handle_) {
        SSL_shutdown(ssl_handle_);
        SSL_free(ssl_handle_);
        ssl_handle_ = nullptr;
    }
    if (ssl_ctx_) {
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
    }
    ssl_active_ = false;
    if (sock_fd_ >= 0) {
        ::close(sock_fd_);
        sock_fd_ = -1;
    }
}

bool MySQLConnection::connect(const std::string &host, uint16_t port, const std::string &user,
                               const std::string &password, uint32_t server_id,
                               const std::string &binlog_file, uint32_t position) {
    if (!open_socket(host, port)) return false;

    set_timeout_ms(timeout_ms_);

    if (!handshake(host, user, password)) {
        std::cerr << "MySQL handshake failed" << std::endl;
        close();
        return false;
    }

    if (!request_binlog_stream(server_id, binlog_file, position)) {
        std::cerr << "Failed to request binlog stream" << std::endl;
        close();
        return false;
    }
    return true;
}

bool MySQLConnection::connect_gtid(const std::string &host, uint16_t port, const std::string &user,
                                   const std::string &password, uint32_t server_id,
                                   const std::string &binlog_file, uint64_t position,
                                   const std::string &gtid_set) {
    if (!open_socket(host, port)) return false;

    set_timeout_ms(timeout_ms_);

    if (!handshake(host, user, password)) {
        std::cerr << "MySQL handshake failed" << std::endl;
        close();
        return false;
    }

    if (!request_binlog_stream_gtid(server_id, binlog_file, position, gtid_set)) {
        std::cerr << "Failed to request binlog stream (GTID)" << std::endl;
        close();
        return false;
    }
    return true;
}

bool MySQLConnection::connect_sql(const std::string &host, uint16_t port, const std::string &user,
                                  const std::string &password) {
    if (!open_socket(host, port)) return false;

    set_timeout_ms(timeout_ms_);
    if (!handshake(host, user, password)) {
        close();
        return false;
    }
    return true;
}

bool MySQLConnection::open_socket(const std::string &host, uint16_t port) {
    close();

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo *result = nullptr;
    const std::string port_str = std::to_string(port);
    int rc = ::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
    if (rc != 0) {
        std::cerr << "Invalid host address: " << ::gai_strerror(rc) << std::endl;
        return false;
    }

    for (addrinfo *rp = result; rp != nullptr; rp = rp->ai_next) {
        sock_fd_ = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock_fd_ < 0) continue;

        if (::connect(sock_fd_, rp->ai_addr, rp->ai_addrlen) == 0) {
            ::freeaddrinfo(result);
            return true;
        }

        ::close(sock_fd_);
        sock_fd_ = -1;
    }

    std::perror("connect");
    ::freeaddrinfo(result);
    return false;
}

bool MySQLConnection::set_timeout_ms(uint32_t timeout_ms) {
    if (sock_fd_ < 0) return false;
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (::setsockopt(sock_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) return false;
    if (::setsockopt(sock_fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) return false;
    return true;
}

bool MySQLConnection::ensure_tls(const std::string &host, uint32_t capability_flags) {
    if (ssl_active_) return true;

    ssl_ctx_ = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx_) return false;

    ssl_handle_ = SSL_new(ssl_ctx_);
    if (!ssl_handle_) return false;

    SSL_set_fd(ssl_handle_, sock_fd_);
    SSL_set_tlsext_host_name(ssl_handle_, host.c_str());

    // SSL Request packet mirrors the initial handshake response header fields.
    std::vector<uint8_t> ssl_req(4, 0);
    ssl_req[0] = capability_flags & 0xff;
    ssl_req[1] = (capability_flags >> 8) & 0xff;
    ssl_req[2] = (capability_flags >> 16) & 0xff;
    ssl_req[3] = (capability_flags >> 24) & 0xff;
    uint32_t max_packet_size = 1024 * 1024 * 16;
    for (int i = 0; i < 4; ++i) ssl_req.push_back((max_packet_size >> (8 * i)) & 0xff);
    ssl_req.push_back(33);
    ssl_req.insert(ssl_req.end(), 23, 0);

    if (!write_packet(ssl_req)) return false;

    if (SSL_connect(ssl_handle_) != 1) {
        ERR_print_errors_fp(stderr);
        return false;
    }

    ssl_active_ = true;
    return true;
}

bool MySQLConnection::handshake(const std::string &host, const std::string &user, const std::string &password) {
    sequence_ = 0;
    Packet packet;
    if (!read_packet(packet)) return false;
    const uint8_t *ptr = packet.payload.data();
    const uint8_t *end = ptr + packet.payload.size();

    if (ptr >= end) return false;
    uint8_t protocol_version = *ptr++;
    (void)protocol_version;
    std::string server_version(reinterpret_cast<const char *>(ptr));
    ptr += server_version.size() + 1;
    if (ptr + 4 > end) return false;
    ptr += 4; // connection id

    std::vector<uint8_t> scramble;
    if (ptr + 8 > end) return false;
    scramble.insert(scramble.end(), ptr, ptr + 8);
    ptr += 8; // auth-plugin-data-part-1
    ptr++;    // filler
    if (ptr + 2 > end) return false;
    uint16_t capability_flags1 = read_uint2(ptr);
    ptr += 2;

    uint16_t capability_flags2 = 0;
    uint8_t auth_plugin_data_len = 0;
    std::string auth_plugin_name = "mysql_native_password";
    if (ptr < end) {
        if (ptr + 2 > end) return false;
        capability_flags2 = read_uint2(ptr);
        ptr += 2;
        uint32_t server_cap = capability_flags1 | (static_cast<uint32_t>(capability_flags2) << 16);
        if (ptr < end) {
            auth_plugin_data_len = *ptr;
            ptr += 10; // reserved bytes
            if (server_cap & CLIENT_PLUGIN_AUTH) {
                size_t len = std::max<size_t>(13, auth_plugin_data_len > 8 ? auth_plugin_data_len - 8 : 0);
                if (ptr + len > end) return false;
                // Insert all but the last byte (which is a null terminator)
                size_t scramble_len = len > 0 ? len - 1 : 0;
                scramble.insert(scramble.end(), ptr, ptr + scramble_len);
                ptr += len;
            } else {
                size_t len = 13; // second part fallback (12 bytes + 1 null terminator)
                if (ptr + len > end) return false;
                // Insert only 12 bytes, excluding the null terminator
                scramble.insert(scramble.end(), ptr, ptr + 12);
                ptr += len;
            }
            if (server_cap & CLIENT_PLUGIN_AUTH && ptr < end) {
                auth_plugin_name.assign(reinterpret_cast<const char *>(ptr));
            }
        }
    }
    scramble_buffer_ = scramble;

    uint32_t desired = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_LONG_PASSWORD | CLIENT_LONG_FLAG |
                       CLIENT_MULTI_RESULTS | CLIENT_DEPRECATE_EOF;
    uint32_t server_capability = capability_flags1 | (static_cast<uint32_t>(capability_flags2) << 16);
    if (server_capability & CLIENT_PLUGIN_AUTH) desired |= CLIENT_PLUGIN_AUTH;
    if (server_capability & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) desired |= CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA;
    if (use_tls_ && (server_capability & CLIENT_SSL)) desired |= CLIENT_SSL;

    uint32_t capability = desired & server_capability;

    if ((capability & CLIENT_SSL) && use_tls_) {
        if (!ensure_tls(host, capability)) return false;
    }

    std::vector<uint8_t> response;
    response.reserve(256);
    response.resize(4, 0);
    response[0] = capability & 0xff;
    response[1] = (capability >> 8) & 0xff;
    response[2] = (capability >> 16) & 0xff;
    response[3] = (capability >> 24) & 0xff;

    uint32_t max_packet_size = 1024 * 1024 * 16;
    for (int i = 0; i < 4; ++i) response.push_back((max_packet_size >> (8 * i)) & 0xff);
    response.push_back(33); // charset (utf8_general_ci)
    response.insert(response.end(), 23, 0);

    response.insert(response.end(), user.begin(), user.end());
    response.push_back(0);

    std::vector<uint8_t> token;
    if (auth_plugin_name == "caching_sha2_password") {
        token = scramble_caching_sha2_password(password, scramble_buffer_);
    } else {
        token = scramble_native_password(password, scramble_buffer_);
    }
    if (capability & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) {
        uint8_t len = static_cast<uint8_t>(token.size());
        response.push_back(len);
    } else {
        response.push_back(static_cast<uint8_t>(token.size()));
    }
    response.insert(response.end(), token.begin(), token.end());

    if (capability & CLIENT_PLUGIN_AUTH) {
        response.insert(response.end(), auth_plugin_name.begin(), auth_plugin_name.end());
        response.push_back(0);
    }

    if (!write_packet(response)) return false;

    Packet auth_resp;
    if (!read_packet(auth_resp)) return false;
    if (auth_resp.payload.empty()) return false;
    if (auth_resp.payload[0] == 0xff) {
        std::cerr << "Authentication failed" << std::endl;
        return false;
    }
    return true;
}

bool MySQLConnection::send_command(uint8_t command, const std::vector<uint8_t> &data) {
    std::vector<uint8_t> payload;
    payload.reserve(data.size() + 1);
    payload.push_back(command);
    payload.insert(payload.end(), data.begin(), data.end());
    return write_packet(payload);
}

bool MySQLConnection::request_binlog_stream(uint32_t server_id, const std::string &binlog_file, uint32_t position) {
    std::vector<uint8_t> data;
    data.reserve(11 + binlog_file.size());
    data.insert(data.end(), {static_cast<uint8_t>(position & 0xff), static_cast<uint8_t>((position >> 8) & 0xff),
                             static_cast<uint8_t>((position >> 16) & 0xff), static_cast<uint8_t>((position >> 24) & 0xff)});
    uint16_t flags = 0;
    data.push_back(flags & 0xff);
    data.push_back((flags >> 8) & 0xff);
    data.push_back(server_id & 0xff);
    data.push_back((server_id >> 8) & 0xff);
    data.push_back((server_id >> 16) & 0xff);
    data.push_back((server_id >> 24) & 0xff);
    data.insert(data.end(), binlog_file.begin(), binlog_file.end());
    data.push_back(0);
    return send_command(COM_BINLOG_DUMP, data);
}

bool MySQLConnection::request_binlog_stream_gtid(uint32_t server_id, const std::string &binlog_file, uint64_t position,
                                                 const std::string &gtid_set) {
    std::vector<uint8_t> data;
    uint16_t flags = 0;
    uint32_t binlog_name_len = static_cast<uint32_t>(binlog_file.size());
    uint32_t gtid_len = static_cast<uint32_t>(gtid_set.size());

    data.reserve(18 + binlog_name_len + gtid_len);
    data.push_back(flags & 0xff);
    data.push_back((flags >> 8) & 0xff);
    data.push_back(server_id & 0xff);
    data.push_back((server_id >> 8) & 0xff);
    data.push_back((server_id >> 16) & 0xff);
    data.push_back((server_id >> 24) & 0xff);

    data.push_back(binlog_name_len & 0xff);
    data.push_back((binlog_name_len >> 8) & 0xff);
    data.push_back((binlog_name_len >> 16) & 0xff);
    data.push_back((binlog_name_len >> 24) & 0xff);
    data.insert(data.end(), binlog_file.begin(), binlog_file.end());

    for (int i = 0; i < 8; ++i) data.push_back(static_cast<uint8_t>((position >> (8 * i)) & 0xff));

    data.push_back(gtid_len & 0xff);
    data.push_back((gtid_len >> 8) & 0xff);
    data.push_back((gtid_len >> 16) & 0xff);
    data.push_back((gtid_len >> 24) & 0xff);
    data.insert(data.end(), gtid_set.begin(), gtid_set.end());

    return send_command(COM_BINLOG_DUMP_GTID, data);
}

bool MySQLConnection::send_query(const std::string &query, std::vector<std::vector<std::string>> &rows) {
    if (!send_command(COM_QUERY, std::vector<uint8_t>(query.begin(), query.end()))) return false;

    Packet resp;
    if (!read_packet(resp)) return false;
    if (resp.payload.empty()) return false;
    if (resp.payload[0] == 0xff) {
        std::cerr << "Query error" << std::endl;
        return false;
    }
    if (resp.payload[0] == 0x00) {
        return true; // OK packet
    }

    uint8_t seq = resp.sequence;
    uint8_t column_count = resp.payload[0];
    for (uint8_t i = 0; i < column_count; ++i) {
        Packet coldef;
        if (!read_packet(coldef)) return false;
        seq = coldef.sequence;
        (void)seq;
    }

    Packet eof_packet;
    if (!read_packet(eof_packet)) return false;

    while (true) {
        Packet row_packet;
        if (!read_packet(row_packet)) return false;
        if (is_eof_packet(row_packet)) break;
        const uint8_t *p = row_packet.payload.data();
        const uint8_t *end = p + row_packet.payload.size();
        std::vector<std::string> row;
        for (uint8_t i = 0; i < column_count; ++i) {
            row.push_back(read_lenenc_string(p, end));
        }
        rows.push_back(std::move(row));
    }
    return true;
}

bool MySQLConnection::read_binlog_packet(BinlogPacket &packet) {
    Packet pkt;
    if (!read_packet(pkt)) return false;
    if (pkt.payload.empty()) return false;
    if (pkt.payload[0] == 0xfe && pkt.payload.size() < 9) return false; // EOF
    packet.event_data = std::move(pkt.payload);
    return true;
}

bool MySQLConnection::recv_all(uint8_t *buf, size_t len) {
    size_t received = 0;
    while (received < len) {
        int n = ssl_active_ ? SSL_read(ssl_handle_, buf + received, static_cast<int>(len - received))
                            : ::recv(sock_fd_, buf + received, len - received, 0);
        if (n <= 0) return false;
        received += static_cast<size_t>(n);
    }
    return true;
}

bool MySQLConnection::send_all(const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = ssl_active_ ? SSL_write(ssl_handle_, buf + sent, static_cast<int>(len - sent))
                            : ::send(sock_fd_, buf + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool MySQLConnection::read_packet(Packet &packet) {
    uint8_t header[4];
    if (!recv_all(header, 4)) return false;
    uint32_t length = header[0] | (header[1] << 8) | (header[2] << 16);
    packet.sequence = header[3];
    packet.payload.resize(length);
    if (!recv_all(packet.payload.data(), length)) return false;
    return true;
}

bool MySQLConnection::write_packet(const std::vector<uint8_t> &payload) {
    uint32_t length = payload.size();
    uint8_t header[4];
    header[0] = length & 0xff;
    header[1] = (length >> 8) & 0xff;
    header[2] = (length >> 16) & 0xff;
    header[3] = sequence_++;
    if (!send_all(header, 4)) return false;
    return send_all(payload.data(), payload.size());
}

} // namespace replicapulse

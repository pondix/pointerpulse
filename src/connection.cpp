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
#include <openssl/pem.h>

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

void dump_hex(const std::string &label, const uint8_t* data, size_t len) {
    std::cerr << label << " (" << len << " bytes): ";
    for (size_t i = 0; i < len && i < 64; ++i) {
        char hex[4];
        snprintf(hex, sizeof(hex), "%02x ", data[i]);
        std::cerr << hex;
        if ((i + 1) % 16 == 0 && i + 1 < len) std::cerr << "\n" << std::string(label.length() + 2, ' ');
    }
    if (len > 64) std::cerr << "... (truncated)";
    std::cerr << std::endl;
}

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

void write_lenenc_int(std::vector<uint8_t> &out, uint64_t value) {
    if (value < 0xfb) {
        out.push_back(static_cast<uint8_t>(value));
    } else if (value <= 0xffff) {
        out.push_back(0xfc);
        out.push_back(static_cast<uint8_t>(value & 0xff));
        out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    } else if (value <= 0xffffff) {
        out.push_back(0xfd);
        out.push_back(static_cast<uint8_t>(value & 0xff));
        out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
        out.push_back(static_cast<uint8_t>((value >> 16) & 0xff));
    } else {
        out.push_back(0xfe);
        for (int i = 0; i < 8; ++i) {
            out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xff));
        }
    }
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
    std::cerr << "[HANDSHAKE] Starting MySQL handshake for user '" << user << "' on host '" << host << "'" << std::endl;

    sequence_ = 0;
    Packet packet;
    if (!read_packet(packet)) {
        std::cerr << "[HANDSHAKE ERROR] Failed to read initial handshake packet from server" << std::endl;
        return false;
    }

    std::cerr << "[HANDSHAKE] Received initial packet, size: " << packet.payload.size() << " bytes" << std::endl;

    const uint8_t *ptr = packet.payload.data();
    const uint8_t *end = ptr + packet.payload.size();

    if (ptr >= end) {
        std::cerr << "[HANDSHAKE ERROR] Initial packet is empty" << std::endl;
        return false;
    }

    uint8_t protocol_version = *ptr++;
    std::cerr << "[HANDSHAKE] Protocol version: " << static_cast<int>(protocol_version) << std::endl;

    const uint8_t *server_ver_end = std::find(ptr, end, static_cast<uint8_t>(0));
    if (server_ver_end == end) {
        std::cerr << "[HANDSHAKE ERROR] Server version string not null-terminated" << std::endl;
        return false;
    }
    std::string server_version(reinterpret_cast<const char *>(ptr), server_ver_end - ptr);
    std::cerr << "[HANDSHAKE] Server version: " << server_version << std::endl;

    ptr = server_ver_end + 1;
    if (ptr + 4 > end) {
        std::cerr << "[HANDSHAKE ERROR] Packet too short for connection ID" << std::endl;
        return false;
    }

    uint32_t connection_id = ptr[0] | (ptr[1] << 8) | (ptr[2] << 16) | (ptr[3] << 24);
    std::cerr << "[HANDSHAKE] Connection ID: " << connection_id << std::endl;
    ptr += 4; // connection id

    std::vector<uint8_t> scramble;
    if (ptr + 8 > end) {
        std::cerr << "[HANDSHAKE ERROR] Packet too short for auth-plugin-data-part-1" << std::endl;
        return false;
    }
    scramble.insert(scramble.end(), ptr, ptr + 8);
    ptr += 8; // auth-plugin-data-part-1
    ptr++;    // filler
    if (ptr + 2 > end) {
        std::cerr << "[HANDSHAKE ERROR] Packet too short for capability flags" << std::endl;
        return false;
    }
    uint16_t capability_flags1 = read_uint2(ptr);
    ptr += 2;

    uint16_t capability_flags2 = 0;
    uint8_t auth_plugin_data_len = 0;
    std::string auth_plugin_name = "mysql_native_password";
    if (ptr + 1 > end) {
        std::cerr << "[HANDSHAKE ERROR] Packet too short for character set" << std::endl;
        return false;
    }
    uint8_t character_set = *ptr++;
    (void)character_set; // currently unused

    if (ptr + 2 > end) {
        std::cerr << "[HANDSHAKE ERROR] Packet too short for status flags" << std::endl;
        return false;
    }
    uint16_t status_flags = read_uint2(ptr);
    ptr += 2;
    (void)status_flags; // currently unused

    if (ptr + 2 > end) {
        std::cerr << "[HANDSHAKE ERROR] Packet too short for extended capability flags" << std::endl;
        return false;
    }
    capability_flags2 = read_uint2(ptr);
    ptr += 2;
    uint32_t server_cap = capability_flags1 | (static_cast<uint32_t>(capability_flags2) << 16);
    std::cerr << "[HANDSHAKE] Server capabilities: 0x" << std::hex << server_cap << std::dec << std::endl;

    if (ptr >= end) {
        std::cerr << "[HANDSHAKE ERROR] Packet too short for auth plugin data length" << std::endl;
        return false;
    }
    auth_plugin_data_len = *ptr++;
    std::cerr << "[HANDSHAKE] Auth plugin data length: " << static_cast<int>(auth_plugin_data_len) << std::endl;

    if (ptr + 10 > end) {
        std::cerr << "[HANDSHAKE ERROR] Packet too short for reserved bytes" << std::endl;
        return false;
    }
    ptr += 10; // reserved bytes

    size_t auth_plugin_data_total_len = auth_plugin_data_len;
    if ((server_cap & CLIENT_PLUGIN_AUTH) && auth_plugin_data_total_len < 8) {
        // Servers occasionally emit 0 here even though 20 bytes follow. Fall back
        // to the protocol default (20 bytes of scramble plus null terminator).
        auth_plugin_data_total_len = 21;
        std::cerr << "[HANDSHAKE WARNING] Auth plugin data length missing/too small; using default 21" << std::endl;
    }

    const uint8_t *plugin_name_start = end;
    bool plugin_name_terminated = false;
    if (server_cap & CLIENT_PLUGIN_AUTH) {
        // Plugin name is the last field and null-terminated. Walk backward to
        // separate it from the scramble data even when the advertised auth
        // plugin data length is missing or incorrect.
        const uint8_t *scan = end;
        if (scan > ptr && *(scan - 1) == 0x00) {
            plugin_name_terminated = true;
            --scan; // drop terminator
        } else {
            std::cerr << "[HANDSHAKE WARNING] Auth plugin name missing null terminator; falling back to default" << std::endl;
        }

        while (scan > ptr && *(scan - 1) != 0x00) {
            --scan;
        }

        if (plugin_name_terminated) {
            plugin_name_start = scan;
            size_t plugin_len = (end - 1) - plugin_name_start;
            auth_plugin_name.assign(reinterpret_cast<const char *>(plugin_name_start), plugin_len);
            if (auth_plugin_name.empty()) {
                auth_plugin_name = "mysql_native_password";
                std::cerr << "[HANDSHAKE WARNING] Empty auth plugin name received; using default mysql_native_password" << std::endl;
            }
        } else {
            // No terminator present. Treat the remaining payload as scramble
            // data and keep the default plugin to avoid mis-parsing random
            // bytes as a plugin name.
            plugin_name_start = end;
        }
    }

    // Consume the remaining data between the reserved bytes and the plugin name
    // as the second part of the scramble. Clamp to the advertised length when
    // possible, but never read past the plugin name boundary discovered above.
    size_t part2_len = plugin_name_start > ptr ? static_cast<size_t>(plugin_name_start - ptr) : 0;
    if (server_cap & CLIENT_SECURE_CONNECTION) {
        size_t expected_len = std::max<size_t>(13, auth_plugin_data_total_len > 8 ? auth_plugin_data_total_len - 8 : 0);
        if (part2_len < expected_len) {
            std::cerr << "[HANDSHAKE WARNING] Auth-plugin-data-part-2 truncated; expected at least "
                      << expected_len << " bytes but only " << part2_len << " available" << std::endl;
        }
        if (part2_len > 0 && ptr[part2_len - 1] == 0x00) {
            --part2_len; // drop trailing null terminator
        }
        scramble.insert(scramble.end(), ptr, ptr + part2_len);
        ptr = plugin_name_start;
    } else {
        size_t fallback_len = std::min<size_t>(12, part2_len);
        scramble.insert(scramble.end(), ptr, ptr + fallback_len);
        ptr = plugin_name_start;
    }

    // Some servers append a trailing null in the combined scramble. Limit to the
    // maximum scramble size expected by the protocol to avoid bleeding into the
    // plugin name field when the server omits auth-plugin-data length.
    if (scramble.size() > 20) {
        scramble.resize(20);
    } else if (!scramble.empty() && scramble.back() == 0x00) {
        scramble.pop_back();
    }
    scramble_buffer_ = scramble;

    std::cerr << "[HANDSHAKE] Auth plugin name: " << auth_plugin_name << std::endl;
    std::cerr << "[HANDSHAKE] Scramble buffer size: " << scramble_buffer_.size() << " bytes (expected 20)" << std::endl;

    dump_hex("[HANDSHAKE] Scramble buffer", scramble_buffer_.data(), scramble_buffer_.size());

    if (scramble_buffer_.size() != 20) {
        std::cerr << "[HANDSHAKE WARNING] ========================================" << std::endl;
        std::cerr << "[HANDSHAKE WARNING] SCRAMBLE BUFFER SIZE IS INCORRECT!" << std::endl;
        std::cerr << "[HANDSHAKE WARNING] Expected: 20 bytes, Got: " << scramble_buffer_.size() << " bytes" << std::endl;
        std::cerr << "[HANDSHAKE WARNING] This WILL cause authentication to fail!" << std::endl;
        std::cerr << "[HANDSHAKE WARNING] ========================================" << std::endl;
    }

    uint32_t desired = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_LONG_PASSWORD | CLIENT_LONG_FLAG |
                       CLIENT_MULTI_RESULTS | CLIENT_DEPRECATE_EOF;
    uint32_t server_capability = capability_flags1 | (static_cast<uint32_t>(capability_flags2) << 16);

    std::cerr << "[HANDSHAKE] Desired client capabilities: 0x" << std::hex << desired << std::dec << std::endl;

    if (server_capability & CLIENT_PLUGIN_AUTH) {
        desired |= CLIENT_PLUGIN_AUTH;
        std::cerr << "[HANDSHAKE] Adding CLIENT_PLUGIN_AUTH to capabilities" << std::endl;
    }
    if (server_capability & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) {
        desired |= CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA;
        std::cerr << "[HANDSHAKE] Adding CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA to capabilities" << std::endl;
    }
    if (use_tls_ && (server_capability & CLIENT_SSL)) {
        desired |= CLIENT_SSL;
        std::cerr << "[HANDSHAKE] Adding CLIENT_SSL to capabilities" << std::endl;
    }

    uint32_t capability = desired & server_capability;
    std::cerr << "[HANDSHAKE] Final negotiated capabilities: 0x" << std::hex << capability << std::dec << std::endl;

    // The initial server handshake packet is sequence 0. The next outgoing
    // packet from the client must start at sequence 1. When TLS is requested
    // an SSLRequest packet (seq=1) is sent, followed by the actual handshake
    // response (seq=2).
    sequence_ = 1;

    if ((capability & CLIENT_SSL) && use_tls_) {
        std::cerr << "[HANDSHAKE] Setting up TLS connection..." << std::endl;
        if (!ensure_tls(host, capability)) {
            std::cerr << "[HANDSHAKE ERROR] TLS setup failed" << std::endl;
            return false;
        }
        std::cerr << "[HANDSHAKE] TLS connection established" << std::endl;
    }

    std::cerr << "[HANDSHAKE] Building authentication response packet..." << std::endl;

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

    std::cerr << "[HANDSHAKE] Generating authentication token using '" << auth_plugin_name << "'..." << std::endl;

    std::vector<uint8_t> token;
    if (auth_plugin_name == "caching_sha2_password") {
        std::cerr << "[HANDSHAKE] Using caching_sha2_password scramble" << std::endl;
        token = scramble_caching_sha2_password(password, scramble_buffer_);
    } else {
        std::cerr << "[HANDSHAKE] Using mysql_native_password scramble" << std::endl;
        token = scramble_native_password(password, scramble_buffer_);
    }

    std::cerr << "[HANDSHAKE] Generated token size: " << token.size() << " bytes" << std::endl;
    dump_hex("[HANDSHAKE] Auth token", token.data(), token.size());

    if (capability & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) {
        write_lenenc_int(response, token.size());
        std::cerr << "[HANDSHAKE] Using lenenc format for auth data (length: " << token.size() << ")" << std::endl;
    } else {
        response.push_back(static_cast<uint8_t>(token.size()));
        std::cerr << "[HANDSHAKE] Using standard format for auth data (length: " << static_cast<int>(token.size()) << ")" << std::endl;
    }
    response.insert(response.end(), token.begin(), token.end());

    if (capability & CLIENT_PLUGIN_AUTH) {
        response.insert(response.end(), auth_plugin_name.begin(), auth_plugin_name.end());
        response.push_back(0);
        std::cerr << "[HANDSHAKE] Including auth plugin name in response: " << auth_plugin_name << std::endl;
    }

    std::cerr << "[HANDSHAKE] Sending authentication response packet (" << response.size() << " bytes)..." << std::endl;

    if (!write_packet(response)) {
        std::cerr << "[HANDSHAKE ERROR] Failed to send authentication response packet" << std::endl;
        return false;
    }

    std::cerr << "[HANDSHAKE] Waiting for authentication response from server..." << std::endl;

    auto read_auth_packet = [this](Packet &pkt) -> bool {
        if (!read_packet(pkt)) return false;
        if (pkt.payload.empty()) return false;
        return true;
    };

    auto fail_with_packet = [&](const Packet &auth_resp) {
        std::cerr << "[HANDSHAKE] Response packet type: 0x" << std::hex
                  << static_cast<int>(auth_resp.payload[0]) << std::dec << std::endl;
        if (auth_resp.payload[0] == 0xff) {
            std::cerr << "[HANDSHAKE ERROR] ========================================" << std::endl;
            std::cerr << "[HANDSHAKE ERROR] AUTHENTICATION FAILED - MySQL Error Packet" << std::endl;
            std::cerr << "[HANDSHAKE ERROR] ========================================" << std::endl;

            if (auth_resp.payload.size() >= 3) {
                uint16_t error_code = auth_resp.payload[1] | (auth_resp.payload[2] << 8);
                std::cerr << "[HANDSHAKE ERROR] MySQL Error Code: " << error_code << std::endl;

                // Parse error message
                if (auth_resp.payload.size() > 3) {
                    size_t msg_start = 3;
                    // Check for SQL state marker '#'
                    if (auth_resp.payload.size() > 9 && auth_resp.payload[3] == '#') {
                        std::string sql_state(reinterpret_cast<const char*>(&auth_resp.payload[4]), 5);
                        std::cerr << "[HANDSHAKE ERROR] SQL State: " << sql_state << std::endl;
                        msg_start = 9;
                    }

                    if (auth_resp.payload.size() > msg_start) {
                        std::string error_message(reinterpret_cast<const char*>(&auth_resp.payload[msg_start]),
                                                 auth_resp.payload.size() - msg_start);
                        std::cerr << "[HANDSHAKE ERROR] Error Message: " << error_message << std::endl;
                    }
                }
            }

            std::cerr << "[HANDSHAKE ERROR] ========================================" << std::endl;
            std::cerr << "[HANDSHAKE ERROR] Troubleshooting Information:" << std::endl;
            std::cerr << "[HANDSHAKE ERROR]   - User: " << user << std::endl;
            std::cerr << "[HANDSHAKE ERROR]   - Host: " << host << std::endl;
            std::cerr << "[HANDSHAKE ERROR]   - Auth Plugin: " << auth_plugin_name << std::endl;
            std::cerr << "[HANDSHAKE ERROR]   - Scramble Buffer Size: " << scramble_buffer_.size() << " bytes" << std::endl;
            std::cerr << "[HANDSHAKE ERROR]   - Token Size: " << token.size() << " bytes" << std::endl;
            std::cerr << "[HANDSHAKE ERROR] ========================================" << std::endl;
            return false;
        }

        return true;
    };

    Packet auth_resp;
    if (!read_auth_packet(auth_resp)) {
        std::cerr << "[HANDSHAKE ERROR] Failed to read authentication response packet from server" << std::endl;
        return false;
    }

    auto read_next_auth = [&](const char *context) -> bool {
        if (!read_packet(auth_resp) || auth_resp.payload.empty()) {
            std::cerr << "[HANDSHAKE ERROR] Failed to read authentication response packet from server" << std::endl;
            return false;
        }

        // Align client sequence with the next expected packet after the
        // server response we just consumed.
        sequence_ = static_cast<uint8_t>(auth_resp.sequence + 1);
        (void)context;
        return true;
    };

    dump_hex("[HANDSHAKE] Auth response packet", auth_resp.payload.data(), auth_resp.payload.size());
    std::cerr << "[HANDSHAKE] Response packet type: 0x" << std::hex << static_cast<int>(auth_resp.payload[0]) << std::dec << std::endl;

    if (!fail_with_packet(auth_resp)) return false;

    if (auth_resp.payload[0] == 0xff) {
        // Error packet - extract detailed error information
        return false;
    }

    auto send_additional_auth = [&](const std::vector<uint8_t> &payload) -> bool {
        if (!write_packet(payload)) {
            std::cerr << "[HANDSHAKE ERROR] Failed to send additional authentication data" << std::endl;
            return false;
        }
        if (!read_auth_packet(auth_resp)) {
            std::cerr << "[HANDSHAKE ERROR] Failed to read follow-up authentication response" << std::endl;
            return false;
        }
        dump_hex("[HANDSHAKE] Auth response packet", auth_resp.payload.data(), auth_resp.payload.size());
        std::cerr << "[HANDSHAKE] Response packet type: 0x" << std::hex << static_cast<int>(auth_resp.payload[0]) << std::dec << std::endl;
        if (!fail_with_packet(auth_resp)) return false;
        return true;
    };

    // Handle authentication method negotiation.
    if (auth_resp.payload[0] == 0xfe) {
        std::cerr << "[HANDSHAKE] Authentication requires additional data (AuthSwitchRequest or AuthMoreData)" << std::endl;
        const uint8_t *p = auth_resp.payload.data() + 1;
        const uint8_t *end = auth_resp.payload.data() + auth_resp.payload.size();
        auth_plugin_name.assign(reinterpret_cast<const char*>(p));
        p += auth_plugin_name.size() + 1; // consume name + null terminator
        scramble_buffer_.assign(p, end);
        std::cerr << "[HANDSHAKE] Switched auth plugin to: " << auth_plugin_name << std::endl;
        dump_hex("[HANDSHAKE] New scramble buffer", scramble_buffer_.data(), scramble_buffer_.size());

        if (auth_plugin_name == "mysql_native_password") {
            token = scramble_native_password(password, scramble_buffer_);
        } else {
            token = scramble_caching_sha2_password(password, scramble_buffer_);
        }

        if (!send_additional_auth(token)) return false;
    }

    if (auth_resp.payload[0] == 0x01 && auth_plugin_name == "caching_sha2_password") {
        uint8_t status = auth_resp.payload.size() > 1 ? auth_resp.payload[1] : 0;
        if (status == 0x03) {
            std::cerr << "[HANDSHAKE] caching_sha2_password fast authentication accepted" << std::endl;
            if (!read_auth_packet(auth_resp)) {
                std::cerr << "[HANDSHAKE ERROR] Failed to read OK packet after fast authentication" << std::endl;
                return false;
            }
            std::cerr << "[HANDSHAKE] Response packet type: 0x" << std::hex << static_cast<int>(auth_resp.payload[0]) << std::dec << std::endl;
            if (!fail_with_packet(auth_resp)) return false;
        } else if (status == 0x04) {
            std::cerr << "[HANDSHAKE] caching_sha2_password requires full authentication" << std::endl;

            if (ssl_active_) {
                std::vector<uint8_t> plain(password.begin(), password.end());
                plain.push_back(0);
                if (!send_additional_auth(plain)) return false;
            } else {
                std::cerr << "[HANDSHAKE] Requesting RSA public key (no TLS)" << std::endl;
                if (!send_additional_auth({0x02})) return false; // Request public key
                if (auth_resp.payload.empty() || auth_resp.payload[0] != 0x01) {
                    std::cerr << "[HANDSHAKE ERROR] Server did not return RSA public key" << std::endl;
                    return false;
                }

                std::string pubkey(reinterpret_cast<const char*>(auth_resp.payload.data() + 1), auth_resp.payload.size() - 1);
                if (!pubkey.empty() && pubkey.back() == '\0') pubkey.pop_back();

                BIO *bio = BIO_new_mem_buf(pubkey.data(), static_cast<int>(pubkey.size()));
                if (!bio) return false;
                RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
                BIO_free(bio);
                if (!rsa) return false;

                std::vector<uint8_t> plain(password.begin(), password.end());
                plain.push_back(0);
                for (size_t i = 0; i < plain.size(); ++i) plain[i] ^= scramble_buffer_[i % scramble_buffer_.size()];

                std::vector<uint8_t> encrypted(RSA_size(rsa));
                int enc_size = RSA_public_encrypt(static_cast<int>(plain.size()), plain.data(), encrypted.data(), rsa,
                                                  RSA_PKCS1_OAEP_PADDING);
                RSA_free(rsa);
                if (enc_size <= 0) return false;
                encrypted.resize(static_cast<size_t>(enc_size));

                if (!send_additional_auth(encrypted)) return false;
            }
        }
    }

    if (auth_resp.payload[0] == 0x00) {
        std::cerr << "[HANDSHAKE] Authentication successful! (OK packet received)" << std::endl;
        return true;
    }

    std::cerr << "[HANDSHAKE] Unexpected response packet type: 0x" << std::hex << static_cast<int>(auth_resp.payload[0]) << std::dec << std::endl;
    return false;
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

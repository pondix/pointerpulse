#include "replicapulse/parser.h"

#include <cmath>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace replicapulse {
namespace {

std::string strip_backticks(const std::string &ident) {
    std::string out;
    out.reserve(ident.size());
    for (char c : ident) {
        if (c != '`') out.push_back(c);
    }
    return out;
}

bool case_insensitive_match(const std::string &text, size_t pos, const char *pattern) {
    size_t i = 0;
    while (pattern[i] != '\0') {
        if (pos + i >= text.size()) return false;
        if (std::tolower(static_cast<unsigned char>(text[pos + i])) !=
            std::tolower(static_cast<unsigned char>(pattern[i]))) {
            return false;
        }
        ++i;
    }
    return true;
}

std::optional<std::pair<std::string, std::string>> detect_ddl_target(const std::string &query, const std::string &default_schema) {
    const char *prefixes[] = {"create table", "alter table", "drop table", "truncate table",
                             "rename table", "create index", "drop index", "create unique index",
                             "create view", "alter view", "drop view", "create temporary table",
                             "drop temporary table"};

    size_t found = std::string::npos;
    const char *matched = nullptr;

    // Only scan first 200 chars for DDL keywords (optimization)
    size_t scan_limit = std::min(query.size(), size_t(200));
    for (size_t pos = 0; pos < scan_limit; ++pos) {
        if (!std::isspace(static_cast<unsigned char>(query[pos])) || pos == 0) {
            for (const auto *p : prefixes) {
                if (case_insensitive_match(query, pos, p)) {
                    found = pos;
                    matched = p;
                    goto done_scanning;
                }
            }
        }
    }
done_scanning:
    if (found == std::string::npos) return std::nullopt;

    size_t start = found + std::strlen(matched);
    while (start < query.size() && std::isspace(static_cast<unsigned char>(query[start]))) ++start;
    if (start >= query.size()) return std::nullopt;

    size_t end = start;
    bool in_backtick = false;
    while (end < query.size()) {
        char c = query[end];
        if (c == '`') {
            in_backtick = !in_backtick;
            ++end;
            continue;
        }
        if (!in_backtick && (std::isspace(static_cast<unsigned char>(c)) || c == '(' || c == ';' || c == ',')) break;
        ++end;
    }
    if (end <= start) return std::nullopt;

    std::string token = strip_backticks(query.substr(start, end - start));
    if (token.empty()) return std::nullopt;

    std::string schema = default_schema;
    std::string table = token;
    auto dot = token.find('.');
    if (dot != std::string::npos) {
        schema = token.substr(0, dot);
        table = token.substr(dot + 1);
    }
    if (schema.empty() || table.empty()) return std::nullopt;
    return std::make_pair(schema, table);
}

const uint8_t DIG2BYTES[10] = {0, 1, 1, 2, 2, 3, 3, 4, 4, 4};

constexpr uint32_t CRC32_TABLE[256] = {
    0x00000000U, 0x77073096U, 0xEE0E612CU, 0x990951BAU, 0x076DC419U, 0x706AF48FU, 0xE963A535U,
    0x9E6495A3U, 0x0EDB8832U, 0x79DCB8A4U, 0xE0D5E91EU, 0x97D2D988U, 0x09B64C2BU, 0x7EB17CBDU,
    0xE7B82D07U, 0x90BF1D91U, 0x1DB71064U, 0x6AB020F2U, 0xF3B97148U, 0x84BE41DEU, 0x1ADAD47DU,
    0x6DDDE4EBU, 0xF4D4B551U, 0x83D385C7U, 0x136C9856U, 0x646BA8C0U, 0xFD62F97AU, 0x8A65C9ECU,
    0x14015C4FU, 0x63066CD9U, 0xFA0F3D63U, 0x8D080DF5U, 0x3B6E20C8U, 0x4C69105EU, 0xD56041E4U,
    0xA2677172U, 0x3C03E4D1U, 0x4B04D447U, 0xD20D85FDU, 0xA50AB56BU, 0x35B5A8FAU, 0x42B2986CU,
    0xDBBBC9D6U, 0xACBCF940U, 0x32D86CE3U, 0x45DF5C75U, 0xDCD60DCFU, 0xABB3FD59U, 0x26D930ACU,
    0x51DE003AU, 0xC8D75180U, 0xBFD06116U, 0x21B4F4B5U, 0x56B3C423U, 0xCFBA9599U, 0xB8BDA50FU,
    0x2802B89EU, 0x5F058808U, 0xC60CD9B2U, 0xB10BE924U, 0x2F6F7C87U, 0x58684C11U, 0xC1611DABU,
    0xB6662D3DU, 0x76DC4190U, 0x01DB7106U, 0x98D220BCU, 0xEFD5102AU, 0x71B18589U, 0x06B6B51FU,
    0x9FBFE4A5U, 0xE8B8D433U, 0x7807C9A2U, 0x0F00F934U, 0x9609A88EU, 0xE10E9818U, 0x7F6A0DBBU,
    0x086D3D2DU, 0x91646C97U, 0xE6635C01U, 0x6B6B51F4U, 0x1C6C6162U, 0x856530D8U, 0xF262004EU,
    0x6C0695EDU, 0x1B01A57BU, 0x8208F4C1U, 0xF50FC457U, 0x65B0D9C6U, 0x12B7E950U, 0x8BBEB8EAU,
    0xFCB9887CU, 0x62DD1DDFU, 0x15DA2D49U, 0x8CD37CF3U, 0xFBD44C65U, 0x4DB26158U, 0x3AB551CEU,
    0xA3BC0074U, 0xD4BB30E2U, 0x4ADFA541U, 0x3DD895D7U, 0xA4D1C46DU, 0xD3D6F4FBU, 0x4369E96AU,
    0x346ED9FCU, 0xAD678846U, 0xDA60B8D0U, 0x44042D73U, 0x33031DE5U, 0xAA0A4C5FU, 0xDD0D7CC9U,
    0x5005713CU, 0x270241AAU, 0xBE0B1010U, 0xC90C2086U, 0x5768B525U, 0x206F85B3U, 0xB966D409U,
    0xCE61E49FU, 0x5EDEF90EU, 0x29D9C998U, 0xB0D09822U, 0xC7D7A8B4U, 0x59B33D17U, 0x2EB40D81U,
    0xB7BD5C3BU, 0xC0BA6CADU, 0xEDB88320U, 0x9ABFB3B6U, 0x03B6E20CU, 0x74B1D29AU, 0xEAD54739U,
    0x9DD277AFU, 0x04DB2615U, 0x73DC1683U, 0xE3630B12U, 0x94643B84U, 0x0D6D6A3EU, 0x7A6A5AA8U,
    0xE40ECF0BU, 0x9309FF9DU, 0x0A00AE27U, 0x7D079EB1U, 0xF00F9344U, 0x8708A3D2U, 0x1E01F268U,
    0x6906C2FEU, 0xF762575DU, 0x806567CBU, 0x196C3671U, 0x6E6B06E7U, 0xFED41B76U, 0x89D32BE0U,
    0x10DA7A5AU, 0x67DD4ACCU, 0xF9B9DF6FU, 0x8EBEEFF9U, 0x17B7BE43U, 0x60B08ED5U, 0xD6D6A3E8U,
    0xA1D1937EU, 0x38D8C2C4U, 0x4FDFF252U, 0xD1BB67F1U, 0xA6BC5767U, 0x3FB506DDU, 0x48B2364BU,
    0xD80D2BDAU, 0xAF0A1B4CU, 0x36034AF6U, 0x41047A60U, 0xDF60EFC3U, 0xA867DF55U, 0x316E8EEFU,
    0x4669BE79U, 0xCB61B38CU, 0xBC66831AU, 0x256FD2A0U, 0x5268E236U, 0xCC0C7795U, 0xBB0B4703U,
    0x220216B9U, 0x5505262FU, 0xC5BA3BBEU, 0xB2BD0B28U, 0x2BB45A92U, 0x5CB36A04U, 0xC2D7FFA7U,
    0xB5D0CF31U, 0x2CD99E8BU, 0x5BDEAE1DU, 0x9B64C2B0U, 0xEC63F226U, 0x756AA39CU, 0x026D930AU,
    0x9C0906A9U, 0xEB0E363FU, 0x72076785U, 0x05005713U, 0x95BF4A82U, 0xE2B87A14U, 0x7BB12BAEU,
    0x0CB61B38U, 0x92D28E9BU, 0xE5D5BE0DU, 0x7CDCEFB7U, 0x0BDBDF21U, 0x86D3D2D4U, 0xF1D4E242U,
    0x68DDB3F8U, 0x1FDA836EU, 0x81BE16CDU, 0xF6B9265BU, 0x6FB077E1U, 0x18B74777U, 0x88085AE6U,
    0xFF0F6A70U, 0x66063BCAU, 0x11010B5CU, 0x8F659EFFU, 0xF862AE69U, 0x616BFFD3U, 0x166CCF45U,
    0xA00AE278U, 0xD70DD2EEU, 0x4E048354U, 0x3903B3C2U, 0xA7672661U, 0xD06016F7U, 0x4969474DU,
    0x3E6E77DBU, 0xAED16A4AU, 0xD9D65ADCU, 0x40DF0B66U, 0x37D83BF0U, 0xA9BCAE53U, 0xDEBB9EC5U,
    0x47B2CF7FU, 0x30B5FFE9U, 0xBDBDF21CU, 0xCABAC28AU, 0x53B39330U, 0x24B4A3A6U, 0xBAD03605U,
    0xCDD70693U, 0x54DE5729U, 0x23D967BFU, 0xB3667A2EU, 0xC4614AB8U, 0x5D681B02U, 0x2A6F2B94U,
    0xB40BBE37U, 0xC30C8EA1U, 0x5A05DF1BU, 0x2D02EF8DU};

uint16_t read_uint16(const uint8_t *p) { return p[0] | (p[1] << 8); }
uint32_t read_uint32(const uint8_t *p) { return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24); }
uint64_t read_uint48(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 6; ++i) v |= (static_cast<uint64_t>(p[i]) << (8 * i));
    return v;
}
uint64_t read_uint64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= (static_cast<uint64_t>(p[i]) << (8 * i));
    return v;
}

uint32_t crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFU;
    for (size_t i = 0; i < len; ++i) {
        uint8_t idx = static_cast<uint8_t>((crc ^ data[i]) & 0xFFU);
        crc = (crc >> 8) ^ CRC32_TABLE[idx];
    }
    return crc ^ 0xFFFFFFFFU;
}

int64_t read_signed(const uint8_t *p, size_t bytes) {
    int64_t v = 0;
    for (size_t i = 0; i < bytes; ++i) v |= (static_cast<int64_t>(p[i]) << (8 * i));
    int64_t sign_bit = static_cast<int64_t>(1ULL << (bytes * 8 - 1));
    if (v & sign_bit) {
        v |= (~0ULL) << (bytes * 8);
    }
    return v;
}

uint64_t read_lenenc_int(const uint8_t *&p, const uint8_t *end) {
    if (p >= end) return 0;
    uint8_t first = *p++;
    if (first < 0xfb) return first;
    if (first == 0xfc) {
        uint64_t v = p[0] | (p[1] << 8);
        p += 2;
        return v;
    }
    if (first == 0xfd) {
        uint64_t v = p[0] | (p[1] << 8) | (p[2] << 16);
        p += 3;
        return v;
    }
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= (static_cast<uint64_t>(p[i]) << (8 * i));
    p += 8;
    return v;
}

std::string read_lenenc_string(const uint8_t *&p, const uint8_t *end) {
    uint64_t len = read_lenenc_int(p, end);
    std::string s(reinterpret_cast<const char *>(p), std::min<uint64_t>(len, end - p));
    p += len;
    return s;
}

ChecksumAlgorithm detect_checksum_alg(const std::vector<uint8_t> &data) {
    if (data.size() < 25) return ChecksumAlgorithm::OFF;
    uint8_t alg = data[data.size() - 5];
    if (alg == static_cast<uint8_t>(ChecksumAlgorithm::CRC32)) return ChecksumAlgorithm::CRC32;
    return ChecksumAlgorithm::OFF;
}

std::vector<bool> read_bitmap(const uint8_t *&p, size_t bits) {
    size_t bytes = (bits + 7) / 8;
    std::vector<bool> out(bits, false);
    for (size_t i = 0; i < bits; ++i) {
        size_t idx = i / 8;
        size_t shift = i % 8;
        if (p[idx] & (1u << shift)) out[i] = true;
    }
    p += bytes;
    return out;
}

int fractional_bytes(uint16_t metadata) { return (metadata + 1) / 2; }

std::string decode_decimal(const uint8_t *&p, uint16_t metadata) {
    uint8_t precision = static_cast<uint8_t>(metadata >> 8);
    uint8_t scale = static_cast<uint8_t>(metadata & 0xff);
    uint8_t intg = precision - scale;
    uint8_t intg0 = intg / 9;
    uint8_t frac0 = scale / 9;
    uint8_t intg0_left = intg - intg0 * 9;
    uint8_t frac0_left = scale - frac0 * 9;
    uint8_t bin_size = intg0 * 4 + DIG2BYTES[intg0_left] + frac0 * 4 + DIG2BYTES[frac0_left];

    std::string buf;
    buf.reserve(precision + 2);
    std::vector<uint8_t> bytes(p, p + bin_size);
    bool positive = (bytes[0] & 0x80) != 0;
    bytes[0] ^= 0x80;
    if (!positive) {
        for (auto &b : bytes) b ^= 0xFF;
        buf.push_back('-');
    }

    size_t idx = 0;
    auto consume_group = [&](uint8_t size, bool pad_left) {
        uint32_t v = 0;
        for (uint8_t i = 0; i < size; ++i) {
            v = (v << 8) | bytes[idx++];
        }
        std::ostringstream oss;
        if (pad_left) oss << std::setw(size == 4 ? 9 : size * 2) << std::setfill('0');
        oss << v;
        buf += oss.str();
    };

    if (intg0_left) consume_group(DIG2BYTES[intg0_left], false);
    for (uint8_t i = 0; i < intg0; ++i) consume_group(4, true);
    if (scale) {
        buf.push_back('.');
        for (uint8_t i = 0; i < frac0; ++i) consume_group(4, true);
        if (frac0_left) consume_group(DIG2BYTES[frac0_left], true);
    }

    p += bin_size;
    return buf;
}

CellValue decode_cell(const TableMetadata &meta, size_t idx, const uint8_t *&p) {
    CellValue cell;
    cell.type = meta.column_types[idx];
    cell.is_null = false;
    cell.present = true;
    uint16_t meta_val = meta.metadata.size() > idx ? meta.metadata[idx] : 0;
    switch (cell.type) {
    case ColumnType::DECIMAL:
    case ColumnType::NEWDECIMAL:
        cell.as_string = decode_decimal(p, meta_val);
        cell.raw.assign(cell.as_string.begin(), cell.as_string.end());
        break;
    case ColumnType::TINY:
        cell.raw.assign(p, p + 1);
        cell.as_string = std::to_string(static_cast<int8_t>(*p));
        p += 1;
        break;
    case ColumnType::SHORT:
        cell.raw.assign(p, p + 2);
        cell.as_string = std::to_string(static_cast<int16_t>(read_uint16(p)));
        p += 2;
        break;
    case ColumnType::INT24: {
        int32_t v = static_cast<int32_t>(read_signed(p, 3));
        cell.raw.assign(p, p + 3);
        cell.as_string = std::to_string(v);
        p += 3;
        break;
    }
    case ColumnType::LONG:
        cell.raw.assign(p, p + 4);
        cell.as_string = std::to_string(static_cast<int32_t>(read_uint32(p)));
        p += 4;
        break;
    case ColumnType::LONGLONG: {
        uint64_t v = read_uint64(p);
        cell.raw.assign(p, p + 8);
        cell.as_string = std::to_string(static_cast<int64_t>(v));
        p += 8;
        break;
    }
    case ColumnType::FLOAT: {
        float f;
        std::memcpy(&f, p, sizeof(float));
        cell.raw.assign(p, p + sizeof(float));
        cell.as_string = std::to_string(f);
        p += sizeof(float);
        break;
    }
    case ColumnType::DOUBLE: {
        double d;
        std::memcpy(&d, p, sizeof(double));
        cell.raw.assign(p, p + sizeof(double));
        cell.as_string = std::to_string(d);
        p += sizeof(double);
        break;
    }
    case ColumnType::TIMESTAMP: {
        uint32_t v = read_uint32(p);
        p += 4;
        cell.as_string = std::to_string(v);
        break;
    }
    case ColumnType::YEAR: {
        uint8_t y = *p++;
        cell.as_string = std::to_string(static_cast<uint16_t>(1900 + y));
        break;
    }
    case ColumnType::DATE: {
        int32_t v = static_cast<int32_t>(read_signed(p, 3));
        p += 3;
        uint32_t day = static_cast<uint32_t>(v & 31);
        uint32_t month = static_cast<uint32_t>((v >> 5) & 15);
        uint32_t year = static_cast<uint32_t>(v >> 9);
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%04u-%02u-%02u", year, month, day);
        cell.as_string = buf;
        break;
    }
    case ColumnType::TIME: {
        int32_t v = static_cast<int32_t>(read_signed(p, 3));
        p += 3;
        int32_t total_seconds = v;
        bool neg = total_seconds < 0;
        if (neg) total_seconds = -total_seconds;
        int h = total_seconds / 3600;
        int m = (total_seconds % 3600) / 60;
        int s = total_seconds % 60;
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%s%02d:%02d:%02d", neg ? "-" : "", h, m, s);
        cell.as_string = buf;
        break;
    }
    case ColumnType::TIME2: {
        // TIME2 is big-endian packed:
        // 3 bytes: sign(1) + hour(10) + minute(6) + second(6) = 23 bits, stored in 24 bits
        // Bit 23 is sign (1=positive, 0=negative), value stored as unsigned with 0x800000 bias
        uint32_t raw = (static_cast<uint32_t>(p[0]) << 16) |
                       (static_cast<uint32_t>(p[1]) << 8) |
                       static_cast<uint32_t>(p[2]);
        p += 3;
        int fbytes = fractional_bytes(meta_val);
        uint32_t fractional = 0;
        for (int i = 0; i < fbytes; ++i) fractional = (fractional << 8) | *p++;

        bool neg = (raw & 0x800000) == 0;
        int32_t packed = neg ? (0x800000 - (raw & 0x7fffff)) : (raw - 0x800000);
        if (packed < 0) packed = -packed;

        int h = (packed >> 12) & 0x3ff;
        int m = (packed >> 6) & 0x3f;
        int s = packed & 0x3f;
        char buf[40];
        if (fbytes > 0) {
            uint32_t frac_scaled = fractional;
            // Scale fractional to 6 digits based on FSP
            for (int i = meta_val; i < 6; ++i) frac_scaled *= 10;
            std::snprintf(buf, sizeof(buf), "%s%02d:%02d:%02d.%0*u", neg ? "-" : "", h, m, s, meta_val, frac_scaled / (meta_val < 6 ? 1 : 1));
        } else {
            std::snprintf(buf, sizeof(buf), "%s%02d:%02d:%02d", neg ? "-" : "", h, m, s);
        }
        cell.as_string = buf;
        break;
    }
    case ColumnType::DATETIME: {
        uint64_t raw = read_uint64(p);
        p += 8;
        uint32_t date = static_cast<uint32_t>(raw / 1000000ULL);
        uint32_t time = static_cast<uint32_t>(raw % 1000000ULL);
        uint32_t sec = time % 100;
        uint32_t min = (time / 100) % 100;
        uint32_t hour = time / 10000;
        uint32_t day = date % 100;
        uint32_t month = (date / 100) % 100;
        uint32_t year = date / 10000;
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%04u-%02u-%02u %02u:%02u:%02u", year, month, day, hour, min, sec);
        cell.as_string = buf;
        break;
    }
    case ColumnType::DATETIME2: {
        uint64_t raw = ((static_cast<uint64_t>(p[0]) << 32) | (static_cast<uint64_t>(p[1]) << 24) |
                        (static_cast<uint64_t>(p[2]) << 16) | (static_cast<uint64_t>(p[3]) << 8) |
                        (static_cast<uint64_t>(p[4])));
        p += 5;
        uint32_t fractional = 0;
        int fbytes = fractional_bytes(meta_val);
        for (int i = 0; i < fbytes; ++i) fractional = (fractional << 8) | *p++;
        uint32_t date = raw >> 17;
        uint32_t time = raw & 0x1ffff;
        uint32_t y = date / (13 * 32);
        uint32_t m = (date % (13 * 32)) / 32;
        uint32_t d = date % 32;
        uint32_t hour = time / (64 * 64);
        uint32_t min = (time / 64) % 64;
        uint32_t sec = time % 64;
        char buf[32];
        if (fbytes > 0)
            std::snprintf(buf, sizeof(buf), "%04u-%02u-%02u %02u:%02u:%02u.%06u", y, m, d, hour, min, sec,
                          fractional * static_cast<uint32_t>(std::pow(10, 6 - meta_val)));
        else
            std::snprintf(buf, sizeof(buf), "%04u-%02u-%02u %02u:%02u:%02u", y, m, d, hour, min, sec);
        cell.as_string = buf;
        break;
    }
    case ColumnType::TIMESTAMP2: {
        // TIMESTAMP2 stores the unix timestamp in big-endian (4 bytes)
        uint32_t v = (static_cast<uint32_t>(p[0]) << 24) |
                     (static_cast<uint32_t>(p[1]) << 16) |
                     (static_cast<uint32_t>(p[2]) << 8) |
                     static_cast<uint32_t>(p[3]);
        p += 4;
        uint32_t fractional = 0;
        int fbytes = fractional_bytes(meta_val);
        for (int i = 0; i < fbytes; ++i) fractional = (fractional << 8) | *p++;
        if (fbytes > 0) {
            char buf[32];
            uint32_t frac_scaled = fractional;
            for (int i = meta_val; i < 6; ++i) frac_scaled *= 10;
            std::snprintf(buf, sizeof(buf), "%u.%0*u", v, meta_val, fractional);
            cell.as_string = buf;
        } else {
            cell.as_string = std::to_string(v);
        }
        break;
    }
    case ColumnType::BIT: {
        uint16_t bits = meta_val;
        uint16_t bytes = (bits + 7) / 8;
        uint64_t val = 0;
        for (uint16_t i = 0; i < bytes; ++i) val = (val << 8) | p[i];
        p += bytes;
        cell.as_string = std::to_string(val);
        break;
    }
    case ColumnType::VAR_STRING:
    case ColumnType::VARCHAR:
    case ColumnType::STRING: {
        // MySQL uses 1-byte length for max_length <= 255, 2-byte for > 255
        uint16_t maxlen = meta_val;
        uint16_t len;
        if (maxlen > 255) {
            len = read_uint16(p);
            p += 2;
        } else {
            len = *p++;
        }
        cell.as_string.assign(reinterpret_cast<const char *>(p), len);
        cell.raw.assign(p, p + len);
        p += len;
        break;
    }
    case ColumnType::ENUM:
    case ColumnType::SET: {
        uint8_t size = static_cast<uint8_t>(meta_val ? meta_val : 1);
        uint64_t v = 0;
        for (uint8_t i = 0; i < size; ++i) v |= static_cast<uint64_t>(p[i]) << (8 * i);
        p += size;
        cell.as_string = std::to_string(v);
        break;
    }
    case ColumnType::JSON:
    case ColumnType::BLOB:
    case ColumnType::TINY_BLOB:
    case ColumnType::MEDIUM_BLOB:
    case ColumnType::LONG_BLOB:
    case ColumnType::GEOMETRY: {
        // MySQL BLOB length prefix is determined by metadata:
        // meta_val specifies the number of bytes for the length field (1-4)
        // TINYBLOB=1, BLOB=2, MEDIUMBLOB=3, LONGBLOB=4
        uint8_t len_bytes = static_cast<uint8_t>(meta_val ? meta_val : 2);
        uint64_t len = 0;
        for (uint8_t i = 0; i < len_bytes && i < 4; ++i) {
            len |= static_cast<uint64_t>(p[i]) << (8 * i);
        }
        p += len_bytes;
        cell.raw.assign(p, p + len);
        cell.as_string.assign(reinterpret_cast<const char *>(p), len);
        p += len;
        break;
    }
    default: {
        // Fallback: assume length coded string
        uint64_t len = read_lenenc_int(p, p + 9);
        cell.raw.assign(p, p + len);
        cell.as_string.assign(reinterpret_cast<const char *>(p), len);
        p += len;
        break;
    }
    }
    return cell;
}

} // namespace

BinlogEventHeader BinlogParser::parse_header(const std::vector<uint8_t> &data) {
    BinlogEventHeader h;
    h.timestamp = read_uint32(data.data());
    h.type = static_cast<EventType>(data[4]);
    h.server_id = read_uint32(data.data() + 5);
    h.event_size = read_uint32(data.data() + 9);
    h.next_position = read_uint32(data.data() + 13);
    h.flags = read_uint16(data.data() + 17);
    return h;
}

bool BinlogParser::parse_event(const std::vector<uint8_t> &data, BinlogEvent &event) {
    if (data.size() < 19) return false;
    event.header = parse_header(data);
    ChecksumAlgorithm alg = checksum_enabled_ ? ChecksumAlgorithm::CRC32 : ChecksumAlgorithm::OFF;
    if (event.header.type == EventType::FORMAT_DESCRIPTION_EVENT) {
        alg = detect_checksum_alg(data);
    }
    bool expect_checksum = (alg == ChecksumAlgorithm::CRC32);

    const std::vector<uint8_t> *payload = &data;
    std::vector<uint8_t> trimmed;
    if (expect_checksum && data.size() >= 23) {
        size_t payload_len = data.size() - 4;
        uint32_t expected_crc = read_uint32(data.data() + payload_len);
        uint32_t actual_crc = crc32(data.data(), payload_len);
        if (expected_crc != actual_crc) {
            std::cerr << "warning: binlog checksum mismatch (expected " << expected_crc << ", got " << actual_crc
                      << "), continuing" << std::endl;
        }
        trimmed.assign(data.begin(), data.begin() + payload_len);
        payload = &trimmed;
    }

    bool ok = true;
    switch (event.header.type) {
    case EventType::FORMAT_DESCRIPTION_EVENT:
        ok = parse_format_description(*payload, event);
        break;
    case EventType::QUERY_EVENT:
        ok = parse_query_event(*payload, event);
        break;
    case EventType::ROTATE_EVENT:
        ok = parse_rotate_event(*payload, event);
        break;
    case EventType::TABLE_MAP_EVENT:
        ok = parse_table_map_event(*payload, event);
        break;
    case EventType::WRITE_ROWS_EVENT_V1:
    case EventType::WRITE_ROWS_EVENT_V2:
        ok = parse_rows_event(*payload, event, false, false);
        break;
    case EventType::DELETE_ROWS_EVENT_V1:
    case EventType::DELETE_ROWS_EVENT_V2:
        ok = parse_rows_event(*payload, event, false, true);
        break;
    case EventType::UPDATE_ROWS_EVENT_V1:
    case EventType::UPDATE_ROWS_EVENT_V2:
        ok = parse_rows_event(*payload, event, true, false);
        break;
    case EventType::XID_EVENT:
        ok = parse_xid_event(*payload, event);
        break;
    case EventType::GTID_EVENT:
    case EventType::ANONYMOUS_GTID_EVENT:
        ok = parse_gtid_event(*payload, event);
        break;
    case EventType::PARTIAL_UPDATE_ROWS_EVENT:
        // MySQL 8.0 partial JSON update - treat like UPDATE_ROWS_V2
        ok = parse_rows_event(*payload, event, true, false);
        break;
    case EventType::TRANSACTION_PAYLOAD_EVENT:
        // MySQL 8.0.20+ compressed transaction payload - skip for now
        // Would require zstd decompression and recursive event parsing
        ok = true;
        break;
    case EventType::PREVIOUS_GTIDS_EVENT:
        ok = parse_previous_gtids_event(*payload, event);
        break;
    default:
        ok = true;
        break;
    }

    if (ok && event.format_desc) {
        event.format_desc->checksum = alg;
        checksum_enabled_ = (alg == ChecksumAlgorithm::CRC32);
    }
    return ok;
}

bool BinlogParser::parse_format_description(const std::vector<uint8_t> &data, BinlogEvent &event) {
    const uint8_t *p = data.data() + 19;
    const uint8_t *end = data.data() + data.size();
    FormatDescriptionEvent fmt;
    fmt.binlog_version = read_uint16(p);
    p += 2;
    fmt.server_version.assign(reinterpret_cast<const char *>(p), 50);
    fmt.server_version = fmt.server_version.c_str();
    p += 50;
    fmt.create_timestamp = read_uint32(p);
    p += 4;
    fmt.header_length = *p++;
    fmt.type_header_lengths.assign(p, end);
    event.format_desc = fmt;
    return true;
}

bool BinlogParser::parse_query_event(const std::vector<uint8_t> &data, BinlogEvent &event) {
    const uint8_t *p = data.data() + 19;
    uint32_t thread_id = read_uint32(p);
    (void)thread_id;
    p += 4;
    uint32_t exec_time = read_uint32(p);
    (void)exec_time;
    p += 4;
    uint8_t schema_len = *p++;
    uint16_t err_code = read_uint16(p);
    (void)err_code;
    p += 2;
    uint16_t status_vars_len = read_uint16(p);
    p += 2;
    p += status_vars_len;
    std::string schema(reinterpret_cast<const char *>(p), schema_len);
    p += schema_len + 1;
    std::string query(reinterpret_cast<const char *>(p), data.data() + data.size() - p);
    QueryEvent q{schema, query};
    event.query = q;
    if (cache_) {
        auto ddl_target = detect_ddl_target(query, schema);
        if (ddl_target) {
            cache_->clear_schema(ddl_target->first, ddl_target->second);
        } else if (!schema.empty()) {
            cache_->clear_schema(schema, "");
        }
    }
    return true;
}

bool BinlogParser::parse_rotate_event(const std::vector<uint8_t> &data, BinlogEvent &event) {
    const uint8_t *p = data.data() + 19;
    RotateEvent rot;
    rot.position = read_uint64(p);
    p += 8;
    rot.next_binlog.assign(reinterpret_cast<const char *>(p), data.data() + data.size() - p);
    event.rotate = rot;
    return true;
}

bool BinlogParser::parse_table_map_event(const std::vector<uint8_t> &data, BinlogEvent &event) {
    const uint8_t *p = data.data() + 19;
    const uint8_t *end = data.data() + data.size();
    TableMapEvent map;
    map.table_id = read_uint48(p);
    p += 6;
    uint16_t flags = read_uint16(p);
    (void)flags;
    p += 2;
    uint8_t schema_len = *p++;
    map.schema.assign(reinterpret_cast<const char *>(p), schema_len);
    p += schema_len + 1;
    uint8_t table_len = *p++;
    map.table.assign(reinterpret_cast<const char *>(p), table_len);
    p += table_len + 1;
    uint64_t column_count = read_lenenc_int(p, end);
    map.column_types.reserve(column_count);
    for (size_t i = 0; i < column_count; ++i) map.column_types.push_back(static_cast<ColumnType>(*p++));
    uint64_t metadata_len = read_lenenc_int(p, end);
    const uint8_t *metadata_end = p + metadata_len;
    for (size_t i = 0; i < column_count && p < metadata_end; ++i) {
        uint16_t meta = 0;
        switch (map.column_types[i]) {
        // 2-byte metadata types
        case ColumnType::VARCHAR:
        case ColumnType::VAR_STRING:
            // max_length in 2 bytes (little-endian)
            meta = read_uint16(p);
            p += 2;
            break;
        case ColumnType::STRING:
            // First byte is real_type, second is field_length
            // For ENUM/SET, real_type indicates pack_length
            meta = (static_cast<uint16_t>(p[0]) << 8) | p[1];
            p += 2;
            break;
        case ColumnType::NEWDECIMAL:
            // precision in first byte, scale in second (big-endian)
            meta = (static_cast<uint16_t>(p[0]) << 8) | p[1];
            p += 2;
            break;
        case ColumnType::BIT:
            // bits%8 in first byte, bits/8 in second byte
            meta = (static_cast<uint16_t>(p[0]) << 8) | p[1];
            p += 2;
            break;
        // 1-byte metadata types
        case ColumnType::FLOAT:
        case ColumnType::DOUBLE:
            // Size in bytes (4 or 8)
            meta = *p++;
            break;
        case ColumnType::BLOB:
        case ColumnType::GEOMETRY:
        case ColumnType::JSON:
            // Number of bytes for length prefix (1-4)
            meta = *p++;
            break;
        case ColumnType::TINY_BLOB:
        case ColumnType::MEDIUM_BLOB:
        case ColumnType::LONG_BLOB:
            // Pack length
            meta = *p++;
            break;
        case ColumnType::TIMESTAMP2:
        case ColumnType::DATETIME2:
        case ColumnType::TIME2:
            // FSP (fractional second precision 0-6)
            meta = *p++;
            break;
        case ColumnType::ENUM:
        case ColumnType::SET:
            // Pack length (1 or 2 bytes for value storage)
            meta = *p++;
            break;
        // No metadata types
        case ColumnType::DECIMAL:
        case ColumnType::TINY:
        case ColumnType::SHORT:
        case ColumnType::LONG:
        case ColumnType::LONGLONG:
        case ColumnType::INT24:
        case ColumnType::YEAR:
        case ColumnType::DATE:
        case ColumnType::TIME:
        case ColumnType::DATETIME:
        case ColumnType::TIMESTAMP:
        case ColumnType::NULL_TYPE:
            // These types have no metadata
            meta = 0;
            break;
        default:
            // Unknown type, try reading 1 byte
            meta = *p++;
            break;
        }
        map.metadata.push_back(meta);
    }
    if (p < metadata_end) p = metadata_end;
    map.null_bitmap = read_bitmap(p, column_count);
    event.table_map = map;

    if (cache_) {
        TableMetadata meta;
        meta.schema = map.schema;
        meta.name = map.table;
        meta.column_types = map.column_types;
        meta.metadata = map.metadata;
        meta.nullable = map.null_bitmap;
        meta.columns.resize(column_count);
        for (size_t i = 0; i < column_count; ++i) {
            meta.columns[i] = "col" + std::to_string(i + 1);
            meta.primary_key.push_back(false);
            meta.unique_key.push_back(false);
        }
        cache_->put(map.table_id, meta);
    }
    return true;
}

bool BinlogParser::parse_rows_event(const std::vector<uint8_t> &data, BinlogEvent &event, bool is_update, bool is_delete) {
    const uint8_t *p = data.data() + 19;
    const uint8_t *end = data.data() + data.size();
    RowsEvent rows;
    rows.is_update = is_update;
    rows.is_delete = is_delete;
    rows.table_id = read_uint48(p);
    p += 6;
    uint16_t flags = read_uint16(p);
    (void)flags;
    p += 2;

    if (event.header.type == EventType::WRITE_ROWS_EVENT_V2 || event.header.type == EventType::UPDATE_ROWS_EVENT_V2 ||
        event.header.type == EventType::DELETE_ROWS_EVENT_V2) {
        uint16_t extra_len = read_uint16(p);
        p += 2;
        p += extra_len - 2;
    }

    uint64_t column_count = read_lenenc_int(p, end);
    if (is_update) {
        rows.included_columns_before = read_bitmap(p, column_count);
        rows.included_columns_after = read_bitmap(p, column_count);
    } else {
        rows.included_columns_after = read_bitmap(p, column_count);
    }

    TableMetadata meta;
    if (!cache_ || !cache_->get(rows.table_id, meta)) {
        QueryEvent fallback{"", "/* skipped row event: missing metadata for table_id=" + std::to_string(rows.table_id) + " */"};
        event.query = fallback;
        return true;
    }

    auto decode_row = [&](const std::vector<bool> &mask, std::vector<CellValue> &out) {
        size_t null_bytes = (mask.size() + 7) / 8;
        const uint8_t *null_ptr = p;
        p += null_bytes;
        for (size_t i = 0, null_idx = 0; i < mask.size(); ++i) {
            if (!mask[i]) continue;
            bool is_null = null_ptr[null_idx / 8] & (1u << (null_idx % 8));
            if (is_null) {
                CellValue cell;
                cell.is_null = true;
                cell.present = true;
                cell.type = meta.column_types[i];
                out.push_back(cell);
            } else {
                out.push_back(decode_cell(meta, i, p));
            }
            ++null_idx;
        }
        // fill placeholders for columns not in mask
        if (out.size() < meta.columns.size()) {
            std::vector<CellValue> expanded;
            expanded.reserve(meta.columns.size());
            size_t included_index = 0;
            for (size_t col = 0; col < meta.columns.size(); ++col) {
                if (mask[col]) {
                    expanded.push_back(out[included_index++]);
                } else {
                    CellValue placeholder;
                    placeholder.present = false;
                    placeholder.type = meta.column_types[col];
                    expanded.push_back(placeholder);
                }
            }
            out.swap(expanded);
        }
    };

    while (p < end) {
        RowChange change;
        if (is_delete) {
            decode_row(rows.included_columns_after, change.before);
        } else if (is_update) {
            decode_row(rows.included_columns_before, change.before);
            decode_row(rows.included_columns_after, change.after);
        } else {
            decode_row(rows.included_columns_after, change.after);
        }
        rows.rows.push_back(std::move(change));
    }

    event.rows = rows;
    return true;
}

bool BinlogParser::parse_xid_event(const std::vector<uint8_t> &data, BinlogEvent &event) {
    const uint8_t *p = data.data() + 19;
    XidEvent xid{read_uint64(p)};
    event.xid = xid;
    return true;
}

bool BinlogParser::parse_gtid_event(const std::vector<uint8_t> &data, BinlogEvent &event) {
    const uint8_t *p = data.data() + 19;
    p += 1; // flags
    std::string uuid;
    char buf[3];
    for (int i = 0; i < 16; ++i) {
        std::snprintf(buf, sizeof(buf), "%02x", p[i]);
        uuid.append(buf);
        if (i == 3 || i == 5 || i == 7 || i == 9) uuid.push_back('-');
    }
    p += 16;
    uint64_t gno = read_uint64(p);
    p += 8;
    GtidEvent gtid{uuid + ":" + std::to_string(gno)};
    event.gtid = gtid;
    return true;
}

bool BinlogParser::parse_previous_gtids_event(const std::vector<uint8_t> &data, BinlogEvent &event) {
    const uint8_t *p = data.data() + 19;
    const uint8_t *end = data.data() + data.size();
    if (p + 8 > end) return false;
    uint64_t sid_count = read_uint64(p);
    p += 8;
    std::ostringstream set;
    auto uuid_to_string = [](const uint8_t *uuid_bytes) {
        std::string uuid;
        char buf[3];
        for (int i = 0; i < 16; ++i) {
            std::snprintf(buf, sizeof(buf), "%02x", uuid_bytes[i]);
            uuid.append(buf);
            if (i == 3 || i == 5 || i == 7 || i == 9) uuid.push_back('-');
        }
        return uuid;
    };

    for (uint64_t sid = 0; sid < sid_count && p < end; ++sid) {
        if (p + 16 > end) break;
        std::string uuid = uuid_to_string(p);
        p += 16;
        if (p + 8 > end) break;
        uint64_t interval_count = read_uint64(p);
        p += 8;
        for (uint64_t i = 0; i < interval_count && p + 16 <= end; ++i) {
            uint64_t start = read_uint64(p);
            uint64_t end_exclusive = read_uint64(p + 8);
            p += 16;
            uint64_t end_inclusive = end_exclusive > 0 ? end_exclusive - 1 : 0;
            if (set.tellp() > 0) set << ",";
            set << uuid << ":" << start << "-" << end_inclusive;
        }
    }

    event.previous_gtids = PreviousGtidsEvent{set.str()};
    return true;
}

} // namespace replicapulse

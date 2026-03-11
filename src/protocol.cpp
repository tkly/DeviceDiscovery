#include "protocol.h"

#include <chrono>
#include <sstream>
#include <stdexcept>

namespace discovery {

namespace {
std::vector<std::string> split(const std::string& text, char delim) {
    std::vector<std::string> parts;
    std::stringstream ss(text);
    std::string item;
    while (std::getline(ss, item, delim)) {
        parts.push_back(item);
    }
    return parts;
}

std::string escape(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
        if (c == '\\' || c == ';' || c == '=') {
            out.push_back('\\');
        }
        out.push_back(c);
    }
    return out;
}

std::string unescape(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    bool escaped = false;
    for (char c : in) {
        if (escaped) {
            out.push_back(c);
            escaped = false;
            continue;
        }
        if (c == '\\') {
            escaped = true;
            continue;
        }
        out.push_back(c);
    }
    return out;
}

size_t find_unescaped(const std::string& s, char target) {
    bool escaped = false;
    for (size_t i = 0; i < s.size(); ++i) {
        if (escaped) {
            escaped = false;
            continue;
        }
        if (s[i] == '\\') {
            escaped = true;
            continue;
        }
        if (s[i] == target) {
            return i;
        }
    }
    return std::string::npos;
}
} // namespace

std::string serialize_kv(const KeyValueMap& map) {
    std::ostringstream oss;
    bool first = true;
    for (const auto& [k, v] : map) {
        if (!first) {
            oss << ';';
        }
        first = false;
        oss << escape(k) << '=' << escape(v);
    }
    return oss.str();
}

KeyValueMap parse_kv(const std::string& text) {
    KeyValueMap out;
    const auto pairs = split(text, ';');
    for (const auto& p : pairs) {
        if (p.empty()) {
            continue;
        }
        const auto eq_pos = find_unescaped(p, '=');
        if (eq_pos == std::string::npos) {
            throw std::runtime_error("invalid kv entry");
        }
        const std::string key = unescape(p.substr(0, eq_pos));
        const std::string value = unescape(p.substr(eq_pos + 1));
        out[key] = value;
    }
    return out;
}

std::string build_envelope(const EncryptedPacket& packet) {
    return "v1|" + bytes_to_hex(packet.iv) + "|" + bytes_to_hex(packet.ciphertext) + "|" +
           bytes_to_hex(packet.tag);
}

EncryptedPacket parse_envelope(const std::string& wire) {
    const auto parts = split(wire, '|');
    if (parts.size() != 4 || parts[0] != "v1") {
        throw std::runtime_error("invalid envelope");
    }
    EncryptedPacket packet;
    packet.iv = hex_to_bytes(parts[1]);
    packet.ciphertext = hex_to_bytes(parts[2]);
    packet.tag = hex_to_bytes(parts[3]);
    return packet;
}

std::string encrypt_message(const std::vector<uint8_t>& key,
                            const KeyValueMap& map) {
    auto packet = aes256gcm_encrypt(key, serialize_kv(map));
    return build_envelope(packet);
}

KeyValueMap decrypt_message(const std::vector<uint8_t>& key,
                            const std::string& wire) {
    auto packet = parse_envelope(wire);
    auto text = aes256gcm_decrypt(key, packet);
    return parse_kv(text);
}

uint64_t unix_seconds() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

} // namespace discovery

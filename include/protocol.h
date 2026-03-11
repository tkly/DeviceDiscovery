#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "crypto.h"

namespace discovery {

using KeyValueMap = std::unordered_map<std::string, std::string>;

std::string serialize_kv(const KeyValueMap& map);
KeyValueMap parse_kv(const std::string& text);

std::string build_envelope(const EncryptedPacket& packet);
EncryptedPacket parse_envelope(const std::string& wire);

std::string encrypt_message(const std::vector<uint8_t>& key,
                            const KeyValueMap& map);

KeyValueMap decrypt_message(const std::vector<uint8_t>& key,
                            const std::string& wire);

uint64_t unix_seconds();

} // namespace discovery

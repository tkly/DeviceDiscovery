#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace discovery {

struct EncryptedPacket {
    std::vector<uint8_t> iv;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;
};

std::vector<uint8_t> hex_to_bytes(const std::string& hex);
std::string bytes_to_hex(const std::vector<uint8_t>& bytes);

EncryptedPacket aes256gcm_encrypt(const std::vector<uint8_t>& key,
                                  const std::string& plaintext);

std::string aes256gcm_decrypt(const std::vector<uint8_t>& key,
                              const EncryptedPacket& packet);

} // namespace discovery

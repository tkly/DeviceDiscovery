#include "crypto.h"

#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/rand.h>

namespace discovery {

namespace {
constexpr size_t kAesKeySize = 32;
constexpr size_t kGcmIvSize = 12;
constexpr size_t kGcmTagSize = 16;

void ensure(bool condition, const char* msg) {
    if (!condition) {
        throw std::runtime_error(msg);
    }
}
} // namespace

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    ensure(hex.size() % 2 == 0, "hex string size must be even");
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        const auto byte = static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16));
        out.push_back(byte);
    }
    return out;
}

std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

EncryptedPacket aes256gcm_encrypt(const std::vector<uint8_t>& key,
                                  const std::string& plaintext) {
    ensure(key.size() == kAesKeySize, "AES-256 key must be 32 bytes");

    EncryptedPacket packet;
    packet.iv.resize(kGcmIvSize);
    ensure(RAND_bytes(packet.iv.data(), static_cast<int>(packet.iv.size())) == 1,
           "RAND_bytes failed");

    packet.ciphertext.resize(plaintext.size());
    packet.tag.resize(kGcmTagSize);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    ensure(ctx != nullptr, "EVP_CIPHER_CTX_new failed");

    int out_len = 0;
    int final_len = 0;

    ensure(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1,
           "EncryptInit cipher failed");
    ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                               static_cast<int>(packet.iv.size()), nullptr) == 1,
           "Set IV len failed");
    ensure(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), packet.iv.data()) == 1,
           "EncryptInit key/iv failed");

    ensure(EVP_EncryptUpdate(ctx, packet.ciphertext.data(), &out_len,
                             reinterpret_cast<const unsigned char*>(plaintext.data()),
                             static_cast<int>(plaintext.size())) == 1,
           "EncryptUpdate failed");

    ensure(EVP_EncryptFinal_ex(ctx, packet.ciphertext.data() + out_len, &final_len) == 1,
           "EncryptFinal failed");

    packet.ciphertext.resize(out_len + final_len);

    ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                               static_cast<int>(packet.tag.size()), packet.tag.data()) == 1,
           "Get GCM tag failed");

    EVP_CIPHER_CTX_free(ctx);
    return packet;
}

std::string aes256gcm_decrypt(const std::vector<uint8_t>& key,
                              const EncryptedPacket& packet) {
    ensure(key.size() == kAesKeySize, "AES-256 key must be 32 bytes");
    ensure(packet.iv.size() == kGcmIvSize, "Invalid GCM IV size");
    ensure(packet.tag.size() == kGcmTagSize, "Invalid GCM tag size");

    std::vector<uint8_t> plaintext(packet.ciphertext.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    ensure(ctx != nullptr, "EVP_CIPHER_CTX_new failed");

    int out_len = 0;
    int final_len = 0;

    ensure(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1,
           "DecryptInit cipher failed");
    ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                               static_cast<int>(packet.iv.size()), nullptr) == 1,
           "Set IV len failed");
    ensure(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), packet.iv.data()) == 1,
           "DecryptInit key/iv failed");

    ensure(EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
                             packet.ciphertext.data(),
                             static_cast<int>(packet.ciphertext.size())) == 1,
           "DecryptUpdate failed");

    ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                               static_cast<int>(packet.tag.size()),
                               const_cast<uint8_t*>(packet.tag.data())) == 1,
           "Set GCM tag failed");

    const int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    ensure(ret == 1, "DecryptFinal failed (auth tag mismatch)");

    plaintext.resize(out_len + final_len);
    return std::string(plaintext.begin(), plaintext.end());
}

} // namespace discovery

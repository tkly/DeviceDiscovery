#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <random>
#include <stdexcept>

#include "protocol.h"

namespace {
constexpr int kDiscoveryPort = 37020;
constexpr int kTimeoutSec = 2;
constexpr size_t kMaxPacket = 2048;

void ensure(bool condition, const char* msg) {
    if (!condition) {
        throw std::runtime_error(msg);
    }
}

std::string random_id() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    const uint64_t v = dis(gen);
    return "req-" + std::to_string(v);
}
} // namespace

int main() {
    try {
        const char* key_hex = std::getenv("DISCOVERY_KEY_HEX");
        ensure(key_hex != nullptr, "DISCOVERY_KEY_HEX is required (32-byte hex key)");
        const auto key = discovery::hex_to_bytes(key_hex);
        ensure(key.size() == 32, "DISCOVERY_KEY_HEX must represent 32 bytes");

        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        ensure(sock >= 0, "socket create failed");

        int broadcast = 1;
        ensure(setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) == 0,
               "setsockopt SO_BROADCAST failed");

        discovery::KeyValueMap req{
            {"type", "DISCOVER"},
            {"request_id", random_id()},
            {"client_id", "pc-client"},
            {"protocol_version", "1"},
            {"need", "control"},
            {"ts", std::to_string(discovery::unix_seconds())},
        };

        const std::string packet = discovery::encrypt_message(key, req);

        sockaddr_in bcast{};
        bcast.sin_family = AF_INET;
        bcast.sin_port = htons(kDiscoveryPort);
        bcast.sin_addr.s_addr = inet_addr("255.255.255.255");

        const ssize_t bcast_sent = sendto(sock, packet.data(), packet.size(), 0,
                                       reinterpret_cast<sockaddr*>(&bcast), sizeof(bcast));

        sockaddr_in loopback{};
        loopback.sin_family = AF_INET;
        loopback.sin_port = htons(kDiscoveryPort);
        loopback.sin_addr.s_addr = inet_addr("127.0.0.1");
        const ssize_t local_sent = sendto(sock, packet.data(), packet.size(), 0,
                                          reinterpret_cast<sockaddr*>(&loopback), sizeof(loopback));

        ensure(bcast_sent >= 0 || local_sent >= 0,
               "sendto failed for both broadcast and loopback");

        std::cout << "[pc] DISCOVER sent, waiting " << kTimeoutSec << "s..." << std::endl;

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(kTimeoutSec);
        bool found_response = false;

        while (true) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                break;
            }

            const auto remaining = deadline - now;
            timeval tv{};
            tv.tv_sec = static_cast<time_t>(std::chrono::duration_cast<std::chrono::seconds>(remaining).count());
            tv.tv_usec = static_cast<suseconds_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(remaining % std::chrono::seconds(1)).count());

            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(sock, &fds);

            const int sel = select(sock + 1, &fds, nullptr, nullptr, &tv);
            if (sel == 0) {
                break;
            }
            if (sel < 0) {
                if (errno == EINTR) {
                    continue;
                }
                throw std::runtime_error("select failed");
            }

            sockaddr_in from{};
            socklen_t from_len = sizeof(from);
            char buf[kMaxPacket];
            const ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
                                       reinterpret_cast<sockaddr*>(&from), &from_len);
            if (n <= 0) {
                if (errno == EINTR) {
                    continue;
                }
                throw std::runtime_error("recvfrom failed");
            }

            try {
                const auto resp = discovery::decrypt_message(key, std::string(buf, buf + n));
                if (resp.at("type") != "ANNOUNCE") {
                    continue;
                }
                found_response = true;
                char ip[INET_ADDRSTRLEN] = {0};
                inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));

                std::cout << "[pc] found device: "
                          << "ip=" << ip
                          << " device_id=" << resp.at("device_id")
                          << " model=" << resp.at("model")
                          << " fw=" << resp.at("fw_version")
                          << " control_port=" << resp.at("control_port")
                          << std::endl;
            } catch (const std::exception& ex) {
                std::cerr << "[pc] bad response: " << ex.what() << std::endl;
            }
        }

        if (!found_response) {
            std::cout << "[pc] no response" << std::endl;
        }

        close(sock);
    } catch (const std::exception& ex) {
        std::cerr << "Fatal: " << ex.what() << std::endl;
        return 1;
    }
    return 0;
}

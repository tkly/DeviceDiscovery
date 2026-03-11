#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>

#include "protocol.h"

namespace {
constexpr int kDiscoveryPort = 37020;
constexpr size_t kMaxPacket = 2048;
constexpr uint64_t kSkewSeconds = 10;
constexpr const char* kMdnsMulticastIp = "224.0.0.251";

void ensure(bool condition, const char* msg) {
    if (!condition) {
        throw std::runtime_error(msg);
    }
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

        int reuse = 1;
        ensure(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == 0,
               "setsockopt SO_REUSEADDR failed");

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(kDiscoveryPort);

        ensure(bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0, "bind failed");

        ip_mreq mreq{};
        mreq.imr_multiaddr.s_addr = inet_addr(kMdnsMulticastIp);
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);
        ensure(setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == 0,
               "setsockopt IP_ADD_MEMBERSHIP failed");

        std::cout << "[device] listening UDP on port " << kDiscoveryPort
                  << " (broadcast + mDNS multicast " << kMdnsMulticastIp << ")" << std::endl;

        while (true) {
            sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);
            char buf[kMaxPacket];
            const ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
                                       reinterpret_cast<sockaddr*>(&client_addr), &client_len);
            if (n <= 0) {
                continue;
            }

            try {
                const std::string wire(buf, buf + n);
                auto req = discovery::decrypt_message(key, wire);
                if (req["type"] != "DISCOVER") {
                    continue;
                }
                const uint64_t ts = std::stoull(req["ts"]);
                const auto now = discovery::unix_seconds();
                if (now > ts + kSkewSeconds || ts > now + kSkewSeconds) {
                    std::cerr << "[device] dropped stale/future request" << std::endl;
                    continue;
                }

                char client_ip[INET_ADDRSTRLEN] = {0};
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

                discovery::KeyValueMap resp{
                    {"type", "ANNOUNCE"},
                    {"request_id", req["request_id"]},
                    {"device_id", "dev-001"},
                    {"model", "EMB-CPP-01"},
                    {"fw_version", "0.1.0"},
                    {"control_port", "46000"},
                    {"auth", "psk-aes256gcm"},
                    {"ts", std::to_string(discovery::unix_seconds())},
                };

                const std::string out = discovery::encrypt_message(key, resp);
                sendto(sock, out.data(), out.size(), 0,
                       reinterpret_cast<sockaddr*>(&client_addr), client_len);
                std::cout << "[device] replied to " << client_ip
                          << " request_id=" << req["request_id"] << std::endl;
            } catch (const std::exception& ex) {
                std::cerr << "[device] request parse/decrypt failed: " << ex.what() << std::endl;
            }
        }

        close(sock);
    } catch (const std::exception& ex) {
        std::cerr << "Fatal: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}

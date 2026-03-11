# DeviceDiscovery

一个使用 **C++ + POSIX Socket + OpenSSL(AES-256-GCM)** 的局域网设备发现示例工程。

该项目包含两部分：
- `device_discovery_server`：设备侧 UDP 监听与应答。
- `pc_discovery_client`：PC 侧发送发现请求并接收设备公告。

---

## 目录
- [功能概览](#功能概览)
- [安全机制](#安全机制)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
  - [1) 构建](#1-构建)
  - [2) 配置密钥](#2-配置密钥)
  - [3) 运行服务端](#3-运行服务端)
  - [4) 运行客户端](#4-运行客户端)
- [网络行为说明](#网络行为说明)
- [常见问题](#常见问题)
- [后续改进建议](#后续改进建议)

---

## 功能概览

- 基于 UDP 的设备发现流程（`DISCOVER` / `ANNOUNCE`）。
- 支持多路径发现：
  - 本地回环（loopback）
  - 广播（broadcast）
  - mDNS 组播地址（`224.0.0.251`）
- 设备端在 mDNS 组播加入失败时，会降级继续运行（不影响广播/回环路径）。

---

## 安全机制

发现消息采用 **AES-256-GCM**（OpenSSL EVP）加密与认证：

- **机密性**：消息内容以密文传输。
- **完整性与认证**：通过 GCM Tag 校验。
- **基础抗重放**：请求携带 `ts` 时间戳，设备端执行时间窗口检查。

> 通过环境变量 `DISCOVERY_KEY_HEX` 注入密钥（64 个十六进制字符 = 32 字节）。

---

## 环境要求

- Linux（当前示例为 POSIX Socket 实现）
- CMake（建议 3.16+）
- 支持 C++17 的编译器
- OpenSSL 开发库

---

## 快速开始

### 1) 构建

```bash
cmake -S . -B build
cmake --build build -j
```

### 2) 配置密钥

```bash
export DISCOVERY_KEY_HEX=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

### 3) 运行服务端

```bash
./build/device_discovery_server
```

### 4) 运行客户端

在另一个终端执行：

```bash
export DISCOVERY_KEY_HEX=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
./build/pc_discovery_client
```

若网络可达且密钥一致，客户端将收到设备应答。

---

## 网络行为说明

- 设备端监听发现端口并处理 `DISCOVER` 请求。
- 客户端会尝试通过广播/回环/mDNS 组播发送发现包。
- 若运行环境不支持 mDNS 组播加入（`IP_ADD_MEMBERSHIP` 失败），设备端会输出告警并继续提供广播/回环发现能力。

---

## 常见问题

### 1) 启动时报 `DISCOVERY_KEY_HEX is required`
未设置环境变量。请先 `export DISCOVERY_KEY_HEX=...`。

### 2) 客户端收不到响应
请检查：
- 服务端与客户端密钥是否一致。
- 防火墙是否放行对应 UDP 端口。
- 是否在同网段或可达网络环境。

### 3) 出现 mDNS join 失败告警
在部分容器/受限网络环境中属常见现象；服务端会自动降级，不会因此退出。

---

## 后续改进建议

- 增加 Windows Socket 适配，完善跨平台支持。
- 引入自动化测试（单元测试 + 端到端发现测试）。
- 控制平面扩展为 TCP + TLS（mTLS/PSK）以提升整体安全性。

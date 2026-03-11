# DeviceDiscovery (C++ 无 Boost + 加密通信)

该实现提供一个最小可运行版本：

- `device_discovery_server`：嵌入式设备侧发现服务端（UDP 监听并应答）。
- `pc_discovery_client`：PC 侧发现客户端（UDP 广播发现并接收设备应答）。

## 安全与加密

发现消息使用 **AES-256-GCM** 加密（OpenSSL EVP）：

- 机密性：消息正文密文传输。
- 完整性/认证：GCM Tag 校验。
- 抗重放基础：请求中携带 `ts`，设备侧做时间窗口检查。

> 密钥通过环境变量 `DISCOVERY_KEY_HEX` 注入（64 hex chars = 32 bytes）。

## 构建

```bash
cmake -S . -B build
cmake --build build -j
```

## 运行

终端 1（设备侧）：

```bash
export DISCOVERY_KEY_HEX=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
./build/device_discovery_server
```

终端 2（PC 侧）：

```bash
export DISCOVERY_KEY_HEX=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
./build/pc_discovery_client
```

如果同网段可达，将看到设备应答输出。

## 说明

- 未使用 Boost。
- 当前为 Linux/POSIX sockets 示例，后续可补 Windows socket 适配层以增强跨平台。
- 控制平面建议后续扩展为 TCP + TLS（mTLS/PSK）。

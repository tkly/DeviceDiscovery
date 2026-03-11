cmake_minimum_required(VERSION 3.16)
project(DeviceDiscoverySecureCpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_library(discovery_common
    src/crypto.cpp
    src/protocol.cpp
)

target_include_directories(discovery_common PUBLIC include)
target_link_libraries(discovery_common PUBLIC OpenSSL::Crypto)

add_executable(device_discovery_server src/device_server.cpp)
target_link_libraries(device_discovery_server PRIVATE discovery_common)

add_executable(pc_discovery_client src/pc_client.cpp)
target_link_libraries(pc_discovery_client PRIVATE discovery_common)

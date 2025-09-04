cmake_minimum_required(VERSION 3.16...3.30)

# set the project name as "VPN"
project(VPN)

# Define the variable NATIVERENDER_ROOT_PATH as the root path of the current source code
set(NATIVERENDER_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})
set(LOCAL_OHOS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../../dep-ohos")
set(CMAKE_PREFIX_PATH ${LOCAL_OHOS_DIR})
set(ENV{PKG_CONFIG_PATH} ${LOCAL_OHOS_DIR}/lib/pkgconfig)
set(OVPN ${CMAKE_CURRENT_SOURCE_DIR}/openvpn3)

add_definitions(-DUSE_TUN_BUILDER)

# Add the header file path to the project
include_directories(
    ${NATIVERENDER_ROOT_PATH}
    ${NATIVERENDER_ROOT_PATH}/include
    ${LOCAL_OHOS_DIR}/include
    ${OVPN}
)
add_subdirectory(fmt)

link_directories(${LOCAL_OHOS_DIR}/lib)

add_definitions(-DUSE_ASIO)

set(OPENSSL_ROOT_DIR "${LOCAL_OHOS_DIR}")
set(OPENSSL_CRYPTO_LIBRARY ${LOCAL_OHOS_DIR}/lib)
set(OPENSSL_INCLUDE_DIR ${LOCAL_OHOS_DIR}/include)
set(SSL_LIBRARY ${LOCAL_OHOS_DIR}/lib/libssl.a ${LOCAL_OHOS_DIR}/lib/libcrypto.a)
find_package(OpenSSL REQUIRED)
add_definitions(-DUSE_OPENSSL)

#set(XXHASH_INCLUDE_DIR ${LOCAL_OHOS_DIR}/include)

# AddressSanitize - use CXX=clang++ CC=clang cmake -DCMAKE_BUILD_TYPE=asan to build with ASAN
# export  UBSAN_OPTIONS=print_stacktrace=1 helps debugging these
set(CMAKE_C_FLAGS_ASAN
        "-fsanitize=address,undefined -fno-sanitize-recover=all -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1"
        CACHE STRING "Flags used by the C compiler during AddressSanitizer builds."
        FORCE)
set(CMAKE_CXX_FLAGS_ASAN
        "-fsanitize=address,undefined -fno-sanitize-recover=all -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1"
        CACHE STRING "Flags used by the C++ compiler during AddressSanitizer builds."
        FORCE)

set(CMAKE_LINKER_FLAGS_ASAN
        "-fsanitize=address,undefined -fno-sanitize-recover=all -fsanitize-address-use-after-scope"
        CACHE STRING "Flags used by the linker during AddressSanitizer builds."
        FORCE)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake
                      ${CMAKE_MODULE_PATH})
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
#set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)
#set(CMAKE_BUILD_TYPE Debug)
#set(CMAKE_BUILD_TYPE Release)

# Build the shared library vpn_client and add the source code file vpn_client.cpp
add_library(vpn_client SHARED
    vpn_client.cpp
    ${OVPN}/client/ovpncli.cpp
    ${OVPN}/openvpn/crypto/data_epoch.cpp)

# Link library files into the vpn_client library
target_link_libraries(vpn_client PUBLIC
                            libace_napi.z.so
                            libhilog_ndk.z.so
                            libnet_connection.so
                            libc++.a
                            ${LOCAL_OHOS_DIR}/lib/libssl.a
                            ${LOCAL_OHOS_DIR}/lib/libcrypto.a
                            ${LOCAL_OHOS_DIR}/lib/libjsoncpp.a
                            fmt)

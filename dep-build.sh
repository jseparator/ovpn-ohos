#!/bin/bash
DIRECTORY="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

INSTALL_PREFIX=$DIRECTORY/dep-ohos
mkdir -p $INSTALL_PREFIX
mkdir -p $INSTALL_PREFIX/include

BUILD_PATH=$DIRECTORY/dep-build
mkdir -p $BUILD_PATH

export TARGET_ARCH=arm64-v8a
export TARGET_PLATFORM=aarch64-linux-ohos
export OHOS_NDK_HOME=~/Library/OpenHarmony/Sdk/15/native
export TOOLCHAIN_BIN=$OHOS_NDK_HOME/llvm/bin

export CC="$TOOLCHAIN_BIN/clang --target=$TARGET_PLATFORM"
export CXX="$TOOLCHAIN_BIN/clang++ --target=$TARGET_PLATFORM"
export AR=$TOOLCHAIN_BIN/llvm-ar
export LD=$TOOLCHAIN_BIN/ld64.lld
export RANLIB=$TOOLCHAIN_BIN/llvm-ranlib
export STRIP=$TOOLCHAIN_BIN/llvm-strip
export NM=$TOOLCHAIN_BIN/llvm-nm

# Sysroot 是包含目标系统库和头文件的目录
export SYSROOT=$OHOS_NDK_HOME/sysroot

export CFLAGS="--sysroot=$SYSROOT -I$SYSROOT/usr/include/$TARGET_PLATFORM -fPIC -D__MUSL__"
export CXXFLAGS="--sysroot=$SYSROOT -I$SYSROOT/usr/include/$TARGET_PLATFORM -fPIC -D__MUSL__"
export CMAKE_REQUIRED_PARAMS="-DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX}"

openssl_version="3.3.2"
cd $BUILD_PATH && curl -LO https://github.com/openssl/openssl/releases/download/openssl-${openssl_version}/openssl-${openssl_version}.tar.gz && tar xzf openssl-${openssl_version}.tar.gz && cd openssl-${openssl_version} && \
    ./Configure linux-aarch64 \
        --prefix=$INSTALL_PREFIX \
        --openssldir=$INSTALL_PREFIX \
        no-asm \
        no-shared \
        -DOPENSSL_SYS_HARMONYOS \
        -DOPENSSL_NO_APPLE_CC_EXTENSIONS \
        -DOPENSSL_NO_APPLE_CRYPTO_RANDOM && make -j4 && make install && \
    cd $BUILD_PATH && rm -rf *

# asio
cd $BUILD_PATH && git clone https://github.com/chriskohlhoff/asio.git && cd asio/asio/include && \
    mv -f asio asio.hpp $INSTALL_PREFIX/include && \
    cd $BUILD_PATH && rm -rf *


json_version="1.9.6"
cd $BUILD_PATH && curl -LO https://github.com/open-source-parsers/jsoncpp/archive/refs/tags/${json_version}.zip && unzip ${json_version}.zip && cd jsoncpp-${json_version} && \
    mkdir build && cd build && \
    cmake .. $CMAKE_REQUIRED_PARAMS -DBUILD_SHARED_LIBS=OFF -DJSONCPP_WITH_TESTS=OFF && \
    make && make install && \
    cd $BUILD_PATH && rm -rf *

cd $DIRECTORY && rm -rf $BUILD_PATH

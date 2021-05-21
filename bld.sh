#!/bin/bash -x
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j $(nproc) O=../test-build

make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j $(nproc) O=../test-build \
DEPMOD=echo \
MODLIB=../test-build/lib/modules/5.10.0-yocto-standard \
INSTALL_FW_PATH=../test-build/lib/firmware modules_install

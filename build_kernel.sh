#!/bin/bash

#init submodules

#main variables
export ARCH=arm64
export RDIR="$(pwd)"
export KBUILD_BUILD_USER="Chanz22"
export TARGET_SOC=s5e9925
export LLVM=1 LLVM_IAS=1
export PLATFORM_VERSION=15
export ANDROID_MAJOR_VERSION=v

export PATH=${RDIR}/toolchains/clang-r416183b/bin:$PATH
export BUILD_CROSS_COMPILE="${RDIR}/toolchains/gcc/arm-gnu-toolchain-14.2.rel1-x86_64-aarch64-none-linux-gnu/bin/aarch64-none-linux-gnu-"

#output dir
if [ ! -d "${RDIR}/out" ]; then
    mkdir -p "${RDIR}/out"
fi

#build dir
if [ ! -d "${RDIR}/build" ]; then
    mkdir -p "${RDIR}/build"
else
    rm -rf "${RDIR}/build" && mkdir -p "${RDIR}/build"
fi

#build options
export ARGS="
-C $(pwd) \
O=$(pwd)/out \
-j$(nproc) \
ARCH=arm64 \
CROSS_COMPILE=${BUILD_CROSS_COMPILE} \
CC=clang
PLATFORM_VERSION=12 \
ANDROID_MAJOR_VERSION=s \
LLVM=1 \
LLVM_IAS=1 \
TARGET_SOC=s5e9925 \
"

#build kernel image
build_kernel(){
    cd "${RDIR}"
    make ${ARGS} clean && make ${ARGS} mrproper
    make ${ARGS} s5e9925-r11sxxx_defconfig
    make ${ARGS} menuconfig
    make ${ARGS}|| exit 1
    cp ${RDIR}/out/arch/arm64/boot/Image* ${RDIR}/build
}

build_kernel
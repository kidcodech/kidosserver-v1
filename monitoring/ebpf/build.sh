#!/bin/bash

set -e

# Build XDP eBPF program
echo "Building XDP eBPF program..."

# Find architecture-specific includes (fixes 'asm/types.h not found' on Debian/Ubuntu)
ARCH=$(uname -m)
ARCH_PATH="${ARCH}-linux-gnu"
INCLUDES=""

if [ -d "/usr/include/${ARCH_PATH}" ]; then
    INCLUDES="-I/usr/include/${ARCH_PATH}"
fi

clang -O2 -target bpf ${INCLUDES} -c xdp_afxdp.c -o xdp_afxdp.o

echo "Build complete! Output: xdp_afxdp.o"

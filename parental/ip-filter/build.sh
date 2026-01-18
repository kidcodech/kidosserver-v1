#!/bin/bash
# Build script for XDP IP Filter eBPF program

set -e

echo "Building XDP IP Filter..."

# Find architecture-specific includes (fixes 'asm/types.h not found' on Debian/Ubuntu)
ARCH=$(uname -m)
ARCH_PATH="${ARCH}-linux-gnu"
INCLUDES=""

if [ -d "/usr/include/${ARCH_PATH}" ]; then
    INCLUDES="-I/usr/include/${ARCH_PATH}"
fi

# Compile the XDP program
clang -O2 -g -target bpf ${INCLUDES} -c xdp_ip_filter.c -o xdp_ip_filter.o

echo "✓ XDP IP Filter built successfully: xdp_ip_filter.o"

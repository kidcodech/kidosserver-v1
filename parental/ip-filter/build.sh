#!/bin/bash
# Build script for XDP IP Filter eBPF program

set -e

echo "Building XDP IP Filter..."

# Compile the XDP program
clang -O2 -g -target bpf -c xdp_ip_filter.c -o xdp_ip_filter.o

echo "✓ XDP IP Filter built successfully: xdp_ip_filter.o"

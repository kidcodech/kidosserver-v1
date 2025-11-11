#!/bin/bash

# Build XDP eBPF program
echo "Building XDP eBPF program..."
clang -O2 -target bpf -c xdp_afxdp.c -o xdp_afxdp.o

echo "Build complete! Output: xdp_afxdp.o"

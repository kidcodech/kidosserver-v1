# XDP eBPF Program for AF_XDP

## Build Instructions

```bash
clang -O2 -target bpf -c xdp_afxdp.c -o xdp_afxdp.o
```

## Requirements

- clang with BPF target support
- kernel headers
- libbpf

## Usage

The compiled `xdp_afxdp.o` will be loaded by the Go sniffer daemon which will:
1. Load the XDP program
2. Attach it to veth-mon interface in monitoring namespace
3. Create AF_XDP socket and register it in xsks_map
4. Receive packets redirected by XDP

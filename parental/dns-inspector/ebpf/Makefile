CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

.PHONY: all clean

all: xdp_dns.o

xdp_dns.o: xdp_dns.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -c xdp_dns.c -o xdp_dns.o

clean:
	rm -f xdp_dns.o

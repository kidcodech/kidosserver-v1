module github.com/kidcodech/kidosserver-v1/parental/dns-inspector

go 1.24.0

toolchain go1.24.10

replace github.com/kidcodech/kidosserver-v1/webserver => ../../webserver

require (
	github.com/asavie/xdp v0.3.3
	github.com/cilium/ebpf v0.4.0
	github.com/google/gopacket v1.1.19
	github.com/kidcodech/kidosserver-v1/webserver v0.0.0-00010101000000-000000000000
)

require (
	github.com/mattn/go-sqlite3 v1.14.22 // indirect
	github.com/vishvananda/netlink v1.1.0 // indirect
	github.com/vishvananda/netns v0.0.0-20191106174202-0a2b9b5464df // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
)

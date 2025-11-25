module github.com/kidcodech/kidosserver-v1/parental/ip-filter

go 1.24.0

toolchain go1.24.10

require (
	github.com/cilium/ebpf v0.12.3
	github.com/kidcodech/kidosserver-v1/webserver v0.0.0
)

replace github.com/kidcodech/kidosserver-v1/webserver => ../../webserver

require (
	github.com/mattn/go-sqlite3 v1.14.22 // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
	golang.org/x/sys v0.15.0 // indirect
)

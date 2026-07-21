package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf Tracer tracer.c -- -I../headers

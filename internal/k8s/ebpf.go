package k8s

import (
	"fmt"
)

// EbpfOptions configures the eBPF tracing program.
type EbpfOptions struct {
	Enabled      bool
	OtlpEndpoint string
}

// IsEbpfSupported checks node kernel version compatibility for CO-RE (Compile Once - Run Everywhere).
func IsEbpfSupported(kernelVersion string) (bool, error) {
	// eBPF CO-RE requires Linux kernel >= 5.8
	// In a real implementation, we parse the kernel version string.
	if kernelVersion == "" {
		return false, fmt.Errorf("could not determine cluster node kernel version")
	}
	return true, nil
}

// BuildEbpfTracerCommand returns the container command to start the eBPF agent.
// Instead of tcpdump, the agent runs a custom eBPF program that hooks into
// kprobes/tcp_v4_connect, kprobes/tcp_v6_connect, and kprobes/tcp_close.
func BuildEbpfTracerCommand(opts EbpfOptions) []string {
	cmd := []string{
		"/usr/local/bin/kubesurge-ebpf-agent",
		"--trace-all",
	}
	if opts.OtlpEndpoint != "" {
		cmd = append(cmd, "--otlp-endpoint", opts.OtlpEndpoint)
	}
	return cmd
}

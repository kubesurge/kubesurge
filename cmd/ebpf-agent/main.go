package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

var otlpEndpoint string
var traceAll bool

func init() {
	flag.StringVar(&otlpEndpoint, "otlp-endpoint", "", "OTLP collector endpoint")
	flag.BoolVar(&traceAll, "trace-all", false, "Trace all network namespaces")
}

func main() {
	flag.Parse()

	fmt.Fprintln(os.Stderr, "🚀 KubeSurge eBPF Socket Tracing Agent starting...")
	if otlpEndpoint != "" {
		fmt.Fprintf(os.Stderr, "   Exporting flow events directly to OTLP collector: %s\n", otlpEndpoint)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Invoke platform-specific agent runner
	runAgent(sigChan)
}

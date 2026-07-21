// Package cmd — capture.go
//
// `kubesurge capture network` is the fully automated, zero-touch capture command.
// It injects an ephemeral container, runs tcpdump non-interactively, and streams
// the resulting .pcap bytes to either a local file or a cloud storage bucket.
//
// This is the "Zero Trust" mode: the human never touches the production pod.
// The binary authenticates, captures, exfiltrates, and self-destructs — fully automated.
//
// .NET analogy: think of this as a BackgroundService / HostedService that
// orchestrates an incident-response workflow end to end without human input.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"os"
	"os/signal"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sexec "k8s.io/client-go/util/exec"

	"github.com/kubesurge/kubesurge/internal/k8s"
	"github.com/kubesurge/kubesurge/internal/sink"
)

// ---------------------------------------------------------------------------
// Flags specific to the capture command
// ---------------------------------------------------------------------------

var (
	// captureDuration controls how long tcpdump runs (e.g. "30s", "2m").
	captureDuration time.Duration

	// storageSinkUrl is the target storage URL string.
	// Supports s3://, gs://, azblob://, file:///, or local file paths.
	storageSinkUrl string

	// captureFilter is a BPF filter expression passed to tcpdump.
	// Example: "port 443 and host 10.0.0.1"
	captureFilter string

	// privileged controls whether the container is injected with privileged: true.
	privileged bool

	// dryRun prints the patch JSON and kubectl equivalent without hitting the API.
	dryRun bool

	// labelSelector fans out capture to all pods matching a label selector.
	// Mutually exclusive with --pod.
	labelSelector string

	// tuiMode displays live packet stats in a Bubble Tea dashboard.
	tuiMode bool

	// captureProtocol automatically translates to BPF filters (e.g. grpc, http2, http, dns).
	captureProtocol string

	// maxCaptureSize limit per file.
	maxCaptureSize string

	// rotateCount number of rotated files.
	rotateCount int

	// otlpEndpoint targets an OTel collector HTTP logs endpoint (e.g. http://localhost:4318/v1/logs)
	otlpEndpoint string

	// ebpfMode uses eBPF socket tracing instead of tcpdump
	ebpfMode bool
)

// newCaptureCmd builds the `capture` command group.
func newCaptureCmd() *cobra.Command {
	captureCmd := &cobra.Command{
		Use:   "capture",
		Short: "Automated diagnostic capture and exfiltration",
		Long:  `Subcommands for zero-touch diagnostic capture from live pods.`,
	}

	captureCmd.AddCommand(newCaptureNetworkCmd())

	return captureCmd
}

// newCaptureNetworkCmd builds `kubesurge capture network`.
func newCaptureNetworkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network",
		Short: "Capture live network traffic from a pod and exfiltrate it",
		Long: `Injects a non-interactive ephemeral container running tcpdump,
streams its output via the Kubernetes exec API, and exfiltrates
the resulting .pcap file directly to a cloud storage bucket or local path.

The pod is NOT restarted. No data touches the worker node's disk.
The ephemeral container terminates automatically when the capture ends.

Target selection (mutually exclusive):
  --pod / -p      Target a single pod by name
  --selector / -l Fan out to all pods matching a label selector

Sink URL formats:
  AWS S3      : s3://my-bucket/
  Google GCS  : gs://my-bucket/
  Azure Blob  : azblob://my-container/
  Local Path  : ./capture.pcap or file:///mnt/pv-volume/`,
		Example: `  # Capture from a single pod and save to S3
  kubesurge capture network -n production -p api-pod --duration 30s --sink s3://my-bucket/

  # Dry-run: preview the injection patch without making API calls
  kubesurge capture network -n production -p api-pod --dry-run

  # Fan out to all pods of a deployment and capture to local files
  kubesurge capture network -n default -l app=my-service --duration 15s --sink /tmp/

  # Capture only HTTPS traffic to Azure Blob Storage
  kubesurge capture network -n production -p api-pod \
    --duration 60s --sink azblob://my-container/ \
    --filter "port 443"`,

		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initK8sClients()
		},

		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate: --pod and --selector are mutually exclusive
			if podName != "" && labelSelector != "" {
				return fmt.Errorf("--pod and --selector are mutually exclusive: specify one or the other")
			}
			if podName == "" && labelSelector == "" {
				return fmt.Errorf("specify a target: --pod (-p) <name> or --selector (-l) <key=value>")
			}
			// If storageSinkUrl is empty and we're not dry-running, default to TUI
			if storageSinkUrl == "" && !dryRun {
				tuiMode = true
			}

			if labelSelector != "" {
				return runCaptureNetworkMulti()
			}
			return runCaptureNetwork(podName)
		},
	}

	cmd.Flags().DurationVar(&captureDuration, "duration", 30*time.Second, "How long to run tcpdump (e.g. 30s, 2m)")
	cmd.Flags().StringVarP(&storageSinkUrl, "sink", "s", "", "Target storage URL (s3://, gs://, azblob://, file:///, or ./local.pcap)")
	cmd.Flags().StringVar(&captureFilter, "filter", "", "BPF filter expression for tcpdump (e.g. 'port 443')")
	cmd.Flags().BoolVar(&privileged, "privileged", false, "Inject container in privileged mode (required on some nodes to capture host-network traffic)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print the injection patch JSON and kubectl equivalent without making any API calls")
	cmd.Flags().StringVarP(&labelSelector, "selector", "l", "", "Label selector to fan out capture to all matching pods (e.g. 'app=my-service')")
	cmd.Flags().BoolVar(&tuiMode, "tui", false, "Display live packet counts and IP talkers in a Terminal UI dashboard")
	cmd.Flags().StringVar(&captureProtocol, "protocol", "", "Protocol profile shortcut to auto-translate BPF filter (grpc, http2, http, dns)")
	cmd.Flags().StringVar(&maxCaptureSize, "max-size", "", "Max PCAP size limit per file (e.g. '500MB' or '10MB') before rotation")
	cmd.Flags().IntVar(&rotateCount, "rotate", 0, "Number of rotated PCAP files to keep (implies --max-size)")
	cmd.Flags().StringVar(&otlpEndpoint, "otlp-endpoint", "", "OpenTelemetry Collector HTTP Logs URL (e.g. http://localhost:4318/v1/logs)")
	cmd.Flags().BoolVar(&ebpfMode, "ebpf", false, "Use eBPF-based socket tracing instead of standard tcpdump raw packet capturing")

	return cmd
}

// ---------------------------------------------------------------------------
// Single-pod capture
// ---------------------------------------------------------------------------

// runCaptureNetwork orchestrates the full automated capture lifecycle for one pod:
//
//	validate → [dry-run | inject → wait → exec tcpdump → stream to sink] → report
func runCaptureNetwork(target string) error {
	if ebpfMode {
		privileged = true
	}
	bold := color.New(color.Bold)
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed, color.Bold)

	fmt.Println()
	bold.Println("  KubeSurge — Automated Network Capture")
	fmt.Printf("     Target   : %s/%s\n", namespace, target)
	fmt.Printf("     Payload  : %s\n", debugImage)
	fmt.Printf("     Duration : %s\n", captureDuration)
	if captureFilter != "" {
		fmt.Printf("     Filter   : %s\n", captureFilter)
	}
	if dryRun {
		yellow.Println("     Mode     : DRY RUN (no API calls will be made)")
	} else {
		fmt.Printf("     Sink     : %s\n", storageSinkUrl)
	}
	fmt.Println()

	// ── Step 1: RBAC preflight ────────────────────────────────────────────
	// Always runs, even in dry-run mode — operators need both the security verdict
	// AND the patch preview to make an informed decision.
	cyan.Println("  [1/5] Checking RBAC permissions...")
	for _, check := range requiredPermissions {
		allowed, _, err := k8s.CheckPermission(clientset, namespace, check.verb, check.resource, check.subresource)
		if err != nil || !allowed {
			red.Printf("  ✗ Missing: %s on %s/%s\n", check.verb, check.resource, check.subresource)
			return fmt.Errorf("RBAC preflight failed — run `kubesurge rbac-check` for details")
		}
	}
	green.Println("  ✓ RBAC OK")
	fmt.Println()

	// ── Step 2: Build injection spec ─────────────────────────────────────
	containerName := fmt.Sprintf("kubesurge-%d", time.Now().Unix())
	lifespanSeconds := int(captureDuration.Seconds()) + 15

	// ── Dry-run path ──────────────────────────────────────────────────────
	if dryRun {
		cyan.Println("  [2/5] Generating injection patch (dry-run)...")
		patchJSON, err := k8s.InjectEphemeralContainer(clientset, namespace, target, k8s.InjectOptions{
			Name:               containerName,
			Image:              debugImage,
			Interactive:        false,
			Privileged:         privileged,
			Command:            []string{"sleep", fmt.Sprintf("%d", lifespanSeconds)},
			AllowHostNamespace: allowHostNamespaces,
			DryRun:             true,
		})
		if err != nil {
			return fmt.Errorf("security preflight failed: %w", err)
		}

		fmt.Println()
		bold.Println("  Patch that would be applied:")
		fmt.Println()
		fmt.Println(patchJSON)
		fmt.Println()
		bold.Println("  Equivalent kubectl command:")
		fmt.Println()
		yellow.Printf("    kubectl debug -n %s %s --image=%s --target=%s\n",
			namespace, target, debugImage, target)
		fmt.Println()
		green.Println("  Dry-run complete. No changes were made to the cluster.")
		fmt.Println()
		return nil
	}

	// ── Step 3: Inject the ephemeral container ────────────────────────────
	cyan.Printf("  [2/5] Injecting non-interactive ephemeral container '%s'...\n", containerName)

	_, err := k8s.InjectEphemeralContainer(clientset, namespace, target, k8s.InjectOptions{
		Name:               containerName,
		Image:              debugImage,
		Interactive:        false,
		Privileged:         privileged,
		Command:            []string{"sleep", fmt.Sprintf("%d", lifespanSeconds)},
		AllowHostNamespace: allowHostNamespaces,
	})
	if err != nil {
		return fmt.Errorf("injection failed: %w", err)
	}
	green.Println("  ✓ Ephemeral container injected")
	fmt.Println()

	// ── Step 4: Build the sink ────────────────────────────────────────────
	var dataSink io.WriteCloser
	var artifactName string
	var sinkErr error

	if storageSinkUrl != "" {
		artifactName = fmt.Sprintf("%s-network-%s.pcap",
			target,
			time.Now().UTC().Format("20060102-150405"),
		)

		var rawSink io.WriteCloser
		rawSink, sinkErr = sink.NewCDKSink(context.Background(), storageSinkUrl, artifactName)
		if sinkErr != nil {
			return fmt.Errorf("failed to initialise storage sink: %w", sinkErr)
		}

		// Wrap in BoundedBufferWriter
		boundedWriter := sink.NewBoundedBufferWriter(rawSink, 50*1024*1024)
		if maxCaptureSize != "" {
			limit, parseErr := parseSize(maxCaptureSize)
			if parseErr != nil {
				rawSink.Close()
				return parseErr
			}
			boundedWriter.MaxCaptureSizeBytes = limit
		}
		dataSink = boundedWriter
		defer dataSink.Close()
	} else {
		// No sink destination: stream packets purely in memory for live TUI
		dataSink = nil
	}

	// ── Step 5: Wait for Running ──────────────────────────────────────────
	if !tuiMode {
		cyan.Println("  [3/5] Waiting for container to reach Running state...")
	}
	if err := k8s.WaitForEphemeralContainer(clientset, namespace, target, containerName, 60*time.Second); err != nil {
		return fmt.Errorf("container failed to start: %w", err)
	}
	if !tuiMode {
		green.Println("  ✓ Container is Running")
		fmt.Println()
	}

	// ── Step 6: Stream tcpdump/eBPF → (sink & TUI) ────────────────────────
	durationSeconds := int(captureDuration.Seconds())
	var traceCmd []string
	if ebpfMode {
		traceCmd = k8s.BuildEbpfTracerCommand(k8s.EbpfOptions{
			Enabled:      true,
			OtlpEndpoint: otlpEndpoint,
		})
	} else {
		traceCmd = buildTcpdumpCommand(durationSeconds, captureFilter)
	}

	if !tuiMode {
		if ebpfMode {
			cyan.Println("  [4/5] Running eBPF tracing agent...")
		} else {
			cyan.Printf("  [4/5] Running tcpdump for %s (streaming to sink)...\n", captureDuration)
		}
		yellow.Printf("        Command: %v\n", traceCmd)
		fmt.Println()
	}

	// Listen for interrupt signals, and add a safety timeout context to prevent hangs.
	timeoutCtx, cancelTimeout := context.WithTimeout(context.Background(), captureDuration+30*time.Second)
	defer cancelTimeout()

	sigCtx, sigStop := signal.NotifyContext(timeoutCtx, os.Interrupt, syscall.SIGTERM)
	defer sigStop()

	var streamErr error
	needParsing := tuiMode || otlpEndpoint != ""

	if needParsing {
		// Set up Live Packet Parser Pipe
		pr, pw := io.Pipe()
		statsChan := make(chan sink.PcapStats, 100)
		parser := sink.NewPcapParser(pr)

		if otlpEndpoint != "" {
			parser.OtlpClient = sink.NewOtlpClient(otlpEndpoint)
			if !tuiMode {
				cyan.Printf("  📡 OTLP Flow Export active: exporting to %s\n", otlpEndpoint)
			}
		}

		// Start background packet parser
		go func() {
			if err := parser.Parse(statsChan); err != nil && err != io.EOF {
				fmt.Printf("  ⚠️ Parser error: %v\n", err)
			}
		}()

		// Determine destination writers
		var targetWriter io.Writer
		if dataSink != nil {
			targetWriter = io.MultiWriter(dataSink, pw)
		} else {
			targetWriter = pw
		}

		if tuiMode {
			// ExecStream in background
			execDone := make(chan error, 1)
			go func() {
				err := k8s.ExecStream(
					sigCtx,
					restConfig,
					clientset,
					k8s.ExecOptions{
						Namespace:     namespace,
						PodName:       target,
						ContainerName: containerName,
						Command:       traceCmd,
						Stdout:        targetWriter,
					},
				)
				pw.Close()
				execDone <- err
			}()

			// Run Bubble Tea dashboard synchronously on main thread
			p := tea.NewProgram(sink.NewTuiModel(statsChan))
			if _, err := p.Run(); err != nil {
				// Fallback: TTY not configured. Run a simple headless stdout print loop.
				fmt.Printf("  [TTY not detected, running in headless monitor mode...]\n")
				for stats := range statsChan {
					fmt.Printf("  Packets: %d | Bytes: %.2f KB | TCP: %d | UDP: %d\n",
						stats.TotalPackets, float64(stats.TotalBytes)/1024.0, stats.TCPCount, stats.UDPCount)
					_ = os.Stdout.Sync()
				}
			}

			// Wait for execution completion
			streamErr = <-execDone
		} else {
			// Background OTLP parsing, ExecStream synchronous on main thread
			streamErr = k8s.ExecStream(
				sigCtx,
				restConfig,
				clientset,
				k8s.ExecOptions{
					Namespace:     namespace,
					PodName:       target,
					ContainerName: containerName,
					Command:       traceCmd,
					Stdout:        targetWriter,
				},
			)
			pw.Close()
		}
	} else {
		// Standard non-TUI, non-OTLP mode
		streamErr = k8s.ExecStream(
			sigCtx,
			restConfig,
			clientset,
			k8s.ExecOptions{
				Namespace:     namespace,
				PodName:       target,
				ContainerName: containerName,
				Command:       traceCmd,
				Stdout:        dataSink,
			},
		)
	}

	if !tuiMode {
		if streamErr != nil {
			exitCode := exitCodeFromErr(streamErr)
			switch {
			case exitCode == 124 || exitCode == 137 || errors.Is(streamErr, context.DeadlineExceeded):
				green.Println("  ✓ Capture completed (duration reached)")
			default:
				return fmt.Errorf("capture execution failed (exit %d): %w", exitCode, streamErr)
			}
		} else {
			green.Println("  ✓ Capture completed")
		}
		fmt.Println()
	}

	// ── Step 7: Finalise and report ───────────────────────────────────────
	if dataSink != nil {
		if err := dataSink.Close(); err != nil {
			return fmt.Errorf("failed to finalise artifact: %w", err)
		}

		if !tuiMode {
			cyan.Println("  [5/5] Finalising artifact...")
			fmt.Println()

			writtenBytes := int64(0)
			if bounded, ok := dataSink.(*sink.BoundedBufferWriter); ok {
				writtenBytes = bounded.TotalBytesWritten()
			}
			if writtenBytes < 24 {
				return fmt.Errorf("capture failed: written file is too small (%d bytes)\n"+
					"  → Verify that tcpdump has NET_RAW capability and BPF filters are valid", writtenBytes)
			}

			green.Println("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			green.Println("  Capture complete.")
			green.Println("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			fmt.Println()
			sinkDisplay := strings.TrimRight(storageSinkUrl, "/")
			bold.Printf("  Artifact: %s/%s (%.2f KB)\n", sinkDisplay, artifactName, float64(writtenBytes)/1024.0)
			fmt.Println()
			yellow.Printf("  Ephemeral container '%s' has exited.\n", containerName)
			yellow.Println("  It remains visible in `kubectl describe` history but consumes no resources.")
			fmt.Println()
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Multi-target capture (--selector)
// ---------------------------------------------------------------------------

// runCaptureNetworkMulti lists all pods matching labelSelector and fans out
// concurrent captures to each, bounded by a semaphore of 5 parallel captures.
func runCaptureNetworkMulti() error {
	bold := color.New(color.Bold)
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)

	fmt.Println()
	bold.Println("  KubeSurge — Multi-Target Network Capture")
	fmt.Printf("     Selector : %s/%s\n", namespace, labelSelector)
	fmt.Printf("     Duration : %s\n", captureDuration)
	fmt.Printf("     Sink     : %s\n", storageSinkUrl)
	fmt.Println()

	// List pods matching the label selector
	cyan.Printf("  Resolving pods matching selector '%s'...\n", labelSelector)
	podList, err := clientset.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return fmt.Errorf("failed to list pods with selector %q: %w", labelSelector, err)
	}
	if len(podList.Items) == 0 {
		return fmt.Errorf("no pods found matching selector %q in namespace %q", labelSelector, namespace)
	}

	bold.Printf("  Found %d pod(s):\n", len(podList.Items))
	for _, p := range podList.Items {
		fmt.Printf("    - %s\n", p.Name)
	}
	fmt.Println()

	// Fan out concurrently, bounded by a semaphore of 5 parallel captures.
	// This prevents overwhelming the API server or the local upload bandwidth.
	const maxParallel = 5
	sem := make(chan struct{}, maxParallel)

	type result struct {
		pod string
		err error
	}

	results := make([]result, len(podList.Items))
	var wg sync.WaitGroup

	for i, p := range podList.Items {
		wg.Add(1)
		go func(idx int, podName string) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire slot
			defer func() { <-sem }() // Release slot

			err := runCaptureNetwork(podName)
			results[idx] = result{pod: podName, err: err}
		}(i, p.Name)
	}

	wg.Wait()

	// Report per-pod results
	fmt.Println()
	bold.Println("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	bold.Printf("  Multi-target capture results (%d pods):\n", len(results))
	bold.Println("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	var failCount int
	for _, r := range results {
		if r.err != nil {
			red.Printf("  FAIL  %s: %v\n", r.pod, r.err)
			failCount++
		} else {
			green.Printf("  OK    %s\n", r.pod)
		}
	}

	fmt.Println()
	if failCount > 0 {
		return fmt.Errorf("%d/%d capture(s) failed — see output above", failCount, len(results))
	}
	green.Printf("  All %d capture(s) completed successfully.\n", len(results))
	fmt.Println()
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildTcpdumpCommand constructs the tcpdump invocation.
// We call 'timeout' directly without wrapping in '/bin/sh -c' to avoid shell
// command injection vulnerabilities from user-supplied filter expressions.
//
// Flags:
//
//	-i any  : capture on all interfaces
//	-U      : packet-buffered mode (immediate flush, critical for streaming)
//	-Z root : stay as root (tcpdump user absent from debugpod)
//	-w -    : write raw pcap stream to stdout
func buildTcpdumpCommand(durationSeconds int, filter string) []string {
	cmd := []string{
		"timeout",
		"--kill-after=2s",
		fmt.Sprintf("%d", durationSeconds),
		"tcpdump",
		"-i", "any",
		"-U",
		"-w", "-",
	}

	finalFilter := filter
	if captureProtocol != "" {
		protoFilter := translateProtocol(captureProtocol)
		if protoFilter != "" {
			if finalFilter != "" {
				finalFilter = fmt.Sprintf("(%s) and (%s)", protoFilter, finalFilter)
			} else {
				finalFilter = protoFilter
			}
		}
	}

	if finalFilter != "" {
		// Split by whitespace and validate tokens to prevent option injection.
		tokens := strings.Fields(finalFilter)
		var safeTokens []string
		for _, token := range tokens {
			// Strip any leading hyphen flags passed inside the filter parameter
			if !strings.HasPrefix(token, "-") {
				safeTokens = append(safeTokens, token)
			}
		}
		if len(safeTokens) > 0 {
			// Append '--' demarcator to force tcpdump to evaluate subsequent args strictly as BPF filter
			cmd = append(cmd, "--")
			cmd = append(cmd, safeTokens...)
		}
	}

	return cmd
}

// translateProtocol maps protocol profiles to BPF filter strings.
func translateProtocol(proto string) string {
	switch strings.ToLower(proto) {
	case "grpc", "http2":
		return "tcp port 50051 or tcp port 80 or tcp port 443 or tcp port 8080"
	case "http":
		return "tcp port 80 or tcp port 8080 or tcp port 8000"
	case "dns":
		return "udp port 53 or tcp port 53"
	default:
		return ""
	}
}

// exitCodeFromErr extracts the process exit code from a Kubernetes exec stream error.
//
// The SPDY stream returns a k8s.io/client-go/util/exec.CodeExitError (concrete struct
// implementing the ExitError interface) when the remote command exits non-zero.
// errors.As works with concrete struct targets but NOT with interface targets, so we
// target CodeExitError directly. If that fails, we walk the chain manually via Unwrap.
// Returns -1 if the error carries no exit code information.
func exitCodeFromErr(err error) int {
	if err == nil {
		return 0
	}
	// Try concrete CodeExitError first (errors.As unwraps through the chain)
	var codeErr k8sexec.CodeExitError
	if errors.As(err, &codeErr) {
		return codeErr.Code
	}
	// Walk the chain manually for any other ExitError implementations
	for e := err; e != nil; e = errors.Unwrap(e) {
		if exitErr, ok := e.(k8sexec.ExitError); ok {
			return exitErr.ExitStatus()
		}
	}
	return -1
}

// parseSize converts size strings like "500MB", "10KB" into raw bytes.
func parseSize(sizeStr string) (int64, error) {
	if sizeStr == "" {
		return 0, nil
	}
	var num int64
	var unit string
	_, err := fmt.Sscanf(sizeStr, "%d%s", &num, &unit)
	if err != nil {
		_, err := fmt.Sscanf(sizeStr, "%d", &num)
		if err != nil {
			return 0, fmt.Errorf("invalid size format: %q (examples: 10MB, 500KB)", sizeStr)
		}
		return num, nil
	}
	switch strings.ToUpper(unit) {
	case "KB", "K":
		return num * 1024, nil
	case "MB", "M":
		return num * 1024 * 1024, nil
	case "GB", "G":
		return num * 1024 * 1024 * 1024, nil
	default:
		return num, nil
	}
}

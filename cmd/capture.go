// Package cmd — capture.go
//
// `kubesurge capture network` is the fully automated, zero-touch capture command.
// It injects an ephemeral container, runs tcpdump non-interactively, and streams
// the resulting .pcap bytes to either a local file or Azure Blob Storage.
//
// This is the "Zero Trust" mode: the human never touches the production pod.
// The binary authenticates, captures, exfiltrates, and self-destructs — fully automated.
//
// .NET analogy: think of this as a BackgroundService / HostedService that
// orchestrates an incident-response workflow end to end without human input.
package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"os"
	"os/signal"
	"syscall"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"k8s.io/client-go/util/exec"

	"github.com/kubesurge/kubesurge/internal/k8s"
	"github.com/kubesurge/kubesurge/internal/sink"
)

// ---------------------------------------------------------------------------
// Flags specific to the capture command
// ---------------------------------------------------------------------------

var (
	// captureDuration controls how long tcpdump runs (e.g. "30s", "2m").
	// .NET analogy: a TimeSpan configuration parameter.
	captureDuration time.Duration

	// storageSinkUrl is the target storage URL string.
	// Supports s3://, gs://, azblob://, file:///, or local file paths.
	// .NET analogy: a connection string configuration.
	storageSinkUrl string

	// captureFilter is a BPF filter expression passed to tcpdump.
	// Example: "port 443 and host 10.0.0.1"
	// .NET analogy: a WHERE clause on a LINQ query.
	captureFilter string

	// privileged controls whether the container is injected with privileged: true.
	privileged bool
)

// newCaptureCmd builds the `capture` command group.
func newCaptureCmd() *cobra.Command {
	captureCmd := &cobra.Command{
		Use:   "capture",
		Short: "Automated diagnostic capture and exfiltration",
		Long:  `Subcommands for zero-touch diagnostic capture from live pods.`,
	}

	// Sub-subcommand: capture network
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

Sink URL formats:
  AWS S3      : s3://my-bucket/
  Google GCS  : gs://my-bucket/
  Azure Blob  : azblob://my-container/
  Local Path  : ./capture.pcap or file:///mnt/pv-volume/`,
		Example: `  # Capture and save directly to AWS S3 bucket
  kubesurge capture network -n production -p api-pod --duration 30s --sink s3://my-bucket/

  # Capture and save directly to local file path
  kubesurge capture network -n default -p my-pod --duration 15s --sink ./capture.pcap --privileged

  # Capture only HTTPS traffic and stream directly to Azure container
  kubesurge capture network -n production -p api-pod \
    --duration 60s --sink azblob://my-container/ \
    --filter "port 443" --privileged`,

		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initK8sClients()
		},

		RunE: func(cmd *cobra.Command, args []string) error {
			if podName == "" {
				return fmt.Errorf("--pod (-p) flag is required")
			}
			// Validate: must have sink configured.
			if storageSinkUrl == "" {
				return fmt.Errorf("specify a sink destination: --sink (-s) <url>")
			}
			return runCaptureNetwork()
		},
	}

	// Register flags specific to this subcommand.
	cmd.Flags().DurationVar(&captureDuration, "duration", 30*time.Second, "How long to run tcpdump (e.g. 30s, 2m)")
	cmd.Flags().StringVarP(&storageSinkUrl, "sink", "s", "", "Target storage URL (s3://my-bucket, gs://my-bucket, azblob://my-container, file:///mnt/my-pv, or ./local.pcap)")
	cmd.Flags().StringVar(&captureFilter, "filter", "", "BPF filter for tcpdump (e.g. 'port 443')")
	cmd.Flags().BoolVar(&privileged, "privileged", false, "Inject container in privileged mode (required on some hardened clusters/nodes to capture traffic)")

	return cmd
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

// runCaptureNetwork orchestrates the full automated capture lifecycle:
//
//	validate → inject → wait → exec tcpdump → stream to sink → report
func runCaptureNetwork() error {
	bold := color.New(color.Bold)
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed, color.Bold)

	fmt.Println()
	bold.Println("  📡 KubeSurge — Automated Network Capture")
	fmt.Printf("     Target   : %s/%s\n", namespace, podName)
	fmt.Printf("     Payload  : %s\n", debugImage)
	fmt.Printf("     Duration : %s\n", captureDuration)
	if captureFilter != "" {
		fmt.Printf("     Filter   : %s\n", captureFilter)
	}
	fmt.Printf("     Sink     : %s\n", storageSinkUrl)

	fmt.Println()

	// ── Step 1: RBAC preflight ────────────────────────────────────────────
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

	// ── Step 2: Build the sink ────────────────────────────────────────────
	// We dynamically construct the file name containing pod name and timestamp.
	artifactName := fmt.Sprintf("%s-network-%s.pcap",
		podName,
		time.Now().UTC().Format("20060102-150405"),
	)

	rawSink, sinkErr := sink.NewCDKSink(context.Background(), storageSinkUrl, artifactName)
	if sinkErr != nil {
		return fmt.Errorf("failed to initialise storage sink: %w", sinkErr)
	}

	// 🛡️ Security Fix 2: Buffer memory boundaries (DoS protection)
	// We wrap the raw sink in a BoundedBufferWriter limited to 50MB. If output writes
	// lag (e.g. slow network upload to Azure), incoming packets are discarded gracefully
	// to prevent local process memory exhaustion and OOM crashes.
	// BoundedBufferWriter automatically closes the rawSink on Close().
	dataSink := sink.NewBoundedBufferWriter(rawSink, 50*1024*1024)
	defer dataSink.Close()

	// ── Step 3: Inject the ephemeral container ────────────────────────────
	containerName := fmt.Sprintf("kubesurge-%d", time.Now().Unix())

	cyan.Printf("  [2/5] Injecting non-interactive ephemeral container '%s'...\n", containerName)

	// Calculate container lifespan (capture duration + 15 seconds safety window)
	lifespanSeconds := int(captureDuration.Seconds()) + 15

	err := k8s.InjectEphemeralContainer(clientset, namespace, podName, k8s.InjectOptions{
		Name:               containerName,
		Image:              debugImage,
		Interactive:        false,                                                 // No stdin/tty — fully automated, zero human access
		Privileged:         privileged,                                            // Bypasses capability drops on hardened clusters/kind nodes
		Command:            []string{"sleep", fmt.Sprintf("%d", lifespanSeconds)}, // Dynamic self-destruction entrypoint
		TargetContainer:    "",                                                    // Default empty network-only namespace attachment
		AllowHostNamespace: allowHostNamespaces,
	})

	if err != nil {
		return fmt.Errorf("injection failed: %w", err)
	}
	green.Println("  ✓ Ephemeral container injected")
	fmt.Println()

	// ── Step 4: Wait for Running ──────────────────────────────────────────
	cyan.Println("  [3/5] Waiting for container to reach Running state...")
	err = k8s.WaitForEphemeralContainer(clientset, namespace, podName, containerName, 60*time.Second)
	if err != nil {
		return fmt.Errorf("container failed to start: %w", err)
	}
	green.Println("  ✓ Container is Running")
	fmt.Println()

	// ── Step 5: Stream tcpdump → sink ────────────────────────────────────
	// Build the tcpdump command. -i any captures on all interfaces.
	// -w - writes to stdout (which we intercept via the exec API).
	// timeout <N> ensures the container terminates itself after N seconds.
	durationSeconds := int(captureDuration.Seconds())
	tcpdumpCmd := buildTcpdumpCommand(durationSeconds, captureFilter)

	cyan.Printf("  [4/5] Running tcpdump for %s (streaming to sink)...\n", captureDuration)
	yellow.Printf("        Command: %v\n", tcpdumpCmd)
	fmt.Println()

	// 🛡️ Security Fix 4: Client-side context cancellation (Ctrl-C handling)
	// Listen for interrupt signals to cancel the stream request gracefully.
	sigCtx, sigStop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer sigStop()

	// k8s.ExecStream opens an SPDY connection to the container and connects
	// its stdout to our sink's io.Writer.
	err = k8s.ExecStream(
		sigCtx,
		restConfig,
		clientset,
		k8s.ExecOptions{
			Namespace:     namespace,
			PodName:       podName,
			ContainerName: containerName,
			Command:       tcpdumpCmd,
			Stdout:        dataSink, // dataSink implements io.Writer
		},
	)
	if err != nil {
		// Evaluate the remotecommand exit status code.
		// timeout returns exit status 124 on successful runtime duration termination.
		if exitErr, ok := err.(exec.ExitError); ok && exitErr.ExitStatus() == 124 {
			green.Println("  ✓ Capture completed successfully (timeout reached)")
		} else {
			return fmt.Errorf("capture execution failed: %w", err)
		}
	} else {
		green.Println("  ✓ Capture completed successfully")
	}
	fmt.Println()

	// ── Step 6: Report ───────────────────────────────────────────────────
	// Flush and close the sink, then print the artifact location.
	if err := dataSink.Close(); err != nil {
		return fmt.Errorf("failed to finalise artifact: %w", err)
	}

	cyan.Println("  [5/5] Finalising artifact...")
	fmt.Println()

	// 🛡️ Security Fix 2: Verify written packet capture bytes to detect failure
	// A valid PCAP file must contain at least a 24-byte global header.
	writtenBytes := dataSink.TotalBytesWritten()
	if writtenBytes < 24 {
		return fmt.Errorf("capture exfiltration failed: written file is empty or corrupted (only %d bytes written)\n"+
			"  → Verify that tcpdump has net-admin/root privileges and that your BPF filters are valid", writtenBytes)
	}

	green.Println("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	green.Println("  ✅ Capture complete!")
	green.Println("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	bold.Printf("  Artifact exfiltrated to: %s (blob: %s, size: %.2f KB)\n", storageSinkUrl, artifactName, float64(writtenBytes)/1024.0)

	fmt.Println()
	yellow.Printf("  ⚠  Ephemeral container '%s' has exited (tcpdump process ended).\n", containerName)
	yellow.Println("     It remains visible in `kubectl describe` history but is no longer consuming resources.")
	fmt.Println()

	return nil
}

// buildTcpdumpCommand constructs the shell command string for tcpdump.
// timeout(1) ensures the container process exits cleanly after N seconds,
// which in turn signals EOF to our io.Pipe and allows the sink to finalise.
func buildTcpdumpCommand(durationSeconds int, filter string) []string {
	// We call 'timeout' directly without wrapping in '/bin/sh -c'. This avoids shell
	// command injection vulnerabilities if a user inputs a malicious filter pattern.
	//
	// -i any    → captures on all interfaces
	// -U        → packet-buffered (immediate flush)
	// -Z root   → stay as root (don't drop privileges to tcpdump user which is absent in debugpod)
	// -w -      → write raw pcap stream to stdout
	cmd := []string{
		"timeout",
		fmt.Sprintf("%d", durationSeconds),
		"tcpdump",
		"-i", "any",
		"-U",
		"-Z", "root",
		"-w", "-",
	}

	if filter != "" {
		// Split filter by whitespace and append as individual tokens so they are parsed
		// as raw arguments by the target binary rather than shell commands.
		// Example: "port 80" -> []string{"port", "80"}
		tokens := strings.Fields(filter)
		cmd = append(cmd, tokens...)
	}

	return cmd
}

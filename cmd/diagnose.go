// Package cmd — diagnose.go
//
// `kubesurge diagnose` injects an interactive ephemeral container into a live
// pod and prints the kubectl attach command to connect to it.
//
// This is the "interactive mode" — a developer attaches a terminal and manually
// runs tools. It is useful for ad-hoc investigation.
//
// .NET analogy: think of this as attaching a live Visual Studio debugger to a
// running process — you get full interactive access to the live execution state.
package cmd

import (
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/kubesurge/kubesurge/internal/k8s"
)

// newDiagnoseCmd builds the `diagnose` subcommand.
func newDiagnoseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diagnose",
		Short: "Inject an interactive debug shell into a live pod",
		Long: `Injects an ephemeral debug container into the target pod and
shares its process and network namespaces. You then attach to it
with kubectl for a fully interactive debugging session.

The target pod is NEVER restarted — its live state is preserved.

What you get inside the shell:
  • Full process tree  (ps aux) — see the app's PID 1 and all children
  • Network interfaces (ip addr, ss, netstat) — shared with the app
  • tcpdump           — capture live traffic on the pod's network
  • strace            — trace system calls of any app process by PID
  • curl, grpcurl     — test HTTP/gRPC endpoints from inside the namespace`,
		Example: `  # Debug a crashing API pod
  kubesurge diagnose -n production -p frontend-api-78d9f

  # Use a custom debug image instead of the default debugpod
  kubesurge diagnose -n default -p my-pod --image busybox`,

		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initK8sClients()
		},

		RunE: func(cmd *cobra.Command, args []string) error {
			if podName == "" {
				return fmt.Errorf("--pod (-p) flag is required")
			}
			return runDiagnose()
		},
	}
	return cmd
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

// runDiagnose is the main execution flow for the diagnose command.
// It follows the pattern: validate → inject → wait → instruct.
func runDiagnose() error {
	bold := color.New(color.Bold)
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed, color.Bold)

	fmt.Println()
	bold.Println("  🔬 KubeSurge — Interactive Diagnose")
	fmt.Printf("     Target  : %s/%s\n", namespace, podName)
	fmt.Printf("     Payload : %s\n", debugImage)
	fmt.Println()

	// ── Step 1: RBAC preflight ────────────────────────────────────────────
	// Check permissions before doing anything destructive.
	// .NET analogy: [Authorize] attribute evaluated before the action runs.
	cyan.Println("  [1/3] Checking RBAC permissions...")
	for _, check := range requiredPermissions {
		allowed, _, err := k8s.CheckPermission(clientset, namespace, check.verb, check.resource, check.subresource)
		if err != nil || !allowed {
			red.Printf("  ✗ Missing permission: %s on %s/%s\n", check.verb, check.resource, check.subresource)
			fmt.Println("     Run `kubesurge rbac-check` for a detailed report and fix instructions.")
			return fmt.Errorf("RBAC preflight failed")
		}
	}
	green.Println("  ✓ RBAC OK")
	fmt.Println()

	// ── Step 2: Inject the ephemeral container ────────────────────────────
	// Generate a unique name to avoid collisions on repeated runs.
	// Ephemeral containers are append-only — you can't remove a named one
	// once injected, so each run needs a fresh name.
	containerName := fmt.Sprintf("kubesurge-%d", time.Now().Unix())

	cyan.Printf("  [2/3] Injecting ephemeral container '%s'...\n", containerName)

	// k8s.InjectEphemeralContainer sends a PATCH to the /ephemeralcontainers
	// subresource. This is the key API call — it modifies the pod's runtime
	// spec without restarting any existing containers.
	_, err := k8s.InjectEphemeralContainer(clientset, namespace, podName, k8s.InjectOptions{
		Name:               containerName,
		Image:              debugImage,
		Interactive:        true, // stdin:true, tty:true — needed for a shell
		Privileged:         true, // Required to run strace and see other namespaces
		TargetContainer:    "",   // Empty = share pod's default namespaces
		AllowHostNamespace: allowHostNamespaces,
	})
	if err != nil {
		return fmt.Errorf("injection failed: %w\n  → Common causes: image pull failure, OPA/Gatekeeper policy, PSP restriction", err)
	}
	green.Println("  ✓ Ephemeral container injected")
	fmt.Println()

	// ── Step 3: Wait until the container is Running ───────────────────────
	// Kubernetes doesn't start the container instantly — it has to schedule it,
	// pull the image if not cached, and initialise it. We poll the pod status.
	// .NET analogy: await Task.WhenAll — we're waiting for an async operation.
	cyan.Println("  [3/3] Waiting for container to reach Running state...")

	err = k8s.WaitForEphemeralContainer(clientset, namespace, podName, containerName, 60*time.Second)
	if err != nil {
		return fmt.Errorf("container did not start in time: %w\n  → Check image pull policy and node resources", err)
	}
	green.Println("  ✓ Container is Running")
	fmt.Println()

	// ── Done: Print attach instructions ──────────────────────────────────
	// We intentionally do NOT auto-attach here. Opening a raw SPDY terminal
	// requires the operator to be in foreground; the kubectl command is simpler,
	// more familiar, and lets the user decide when to connect.
	green.Println("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	green.Println("  ✅ Diagnostic payload is live!")
	green.Println("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	bold.Println("  Connect to the debug shell by running:")
	fmt.Println()
	yellow.Printf("    kubectl attach -n %s -c %s -it pod/%s\n", namespace, containerName, podName)
	fmt.Println()
	fmt.Println("  Inside the shell you can run:")
	fmt.Println("    ps aux                    — see ALL processes (including the app)")
	fmt.Println("    tcpdump -i any -nn        — capture live network traffic")
	fmt.Println("    strace -p <PID>           — trace system calls of the app process")
	fmt.Println("    ss -tlnp                  — list open sockets")
	fmt.Println("    curl localhost:<port>     — test the app's HTTP endpoints locally")
	fmt.Println()

	yellow.Printf("  ⚠  The ephemeral container '%s' will appear in `kubectl describe pod/%s`\n", containerName, podName)
	yellow.Println("     and will remain until the pod is deleted. It stops when you exit the shell.")
	fmt.Println()

	return nil
}

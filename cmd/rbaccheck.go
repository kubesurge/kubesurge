// Package cmd — rbaccheck.go
//
// `kubesurge rbac-check` fires SelfSubjectAccessReview requests against the
// Kubernetes API server to verify that the current user has the RBAC permissions
// required to inject an ephemeral container.
//
// .NET analogy: this is a pre-deployment health check or a startup IHostedService
// that validates required service permissions before the application goes live.
package cmd

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/kubesurge/kubesurge/internal/k8s"
)

// newRbacCheckCmd builds the `rbac-check` subcommand.
func newRbacCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rbac-check",
		Short: "Verify RBAC permissions required to inject ephemeral containers",
		Long: `Fires SelfSubjectAccessReview requests against the API server to validate
that your current kubeconfig identity has all permissions kubesurge needs.

Run this before 'diagnose' or 'capture' to catch permission errors early.

Required permissions:
  • pods               — get        (read pod metadata)
  • pods/ephemeralcontainers — patch (inject the debug container)
  • pods/exec          — create     (stream commands into the container)`,
		Example: `  kubesurge rbac-check -n production -p my-api-pod
  kubesurge rbac-check -n default   -p frontend-xyz --kubeconfig /etc/kube/admin.conf`,

		// PersistentPreRunE runs before RunE and initialises the shared k8s clientset.
		// .NET analogy: middleware that runs before the action method.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initK8sClients()
		},

		RunE: func(cmd *cobra.Command, args []string) error {
			return runRbacCheck()
		},
	}
	return cmd
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

// rbacCheck defines the set of permissions kubesurge needs.
// Each entry maps to one SelfSubjectAccessReview call.
type rbacCheck struct {
	description string // Human-readable label for the terminal output
	verb        string // Kubernetes verb: get, patch, create, etc.
	resource    string // Kubernetes resource: pods, pods/exec, etc.
	subresource string // Empty string if not a subresource
}

// requiredPermissions is the full list of checks kubesurge performs.
// If any of these fail, the tool cannot operate safely.
var requiredPermissions = []rbacCheck{
	{
		description: "Read pod metadata",
		verb:        "get",
		resource:    "pods",
		subresource: "",
	},
	{
		description: "Inject ephemeral debug container",
		verb:        "patch",
		resource:    "pods",
		subresource: "ephemeralcontainers",
	},
	{
		description: "Stream commands into container (exec)",
		verb:        "create",
		resource:    "pods",
		subresource: "exec",
	},
}

// runRbacCheck iterates through the required permissions and prints a table.
func runRbacCheck() error {
	bold := color.New(color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow)

	bold.Printf("\n🔐 RBAC Pre-flight Check\n")
	bold.Printf("   Namespace : %s\n", namespace)
	bold.Printf("   Pod       : %s\n\n", podName)

	// Print table header
	fmt.Printf("  %-40s %-25s %s\n", "Permission", "Resource", "Status")
	fmt.Printf("  %s\n", "─────────────────────────────────────────────────────────────────────────")

	allPassed := true

	for _, check := range requiredPermissions {
		// k8s.CheckPermission wraps SelfSubjectAccessReview.
		// The API server evaluates this against its RBAC engine and returns
		// allowed:true/false without actually performing the operation.
		allowed, reason, err := k8s.CheckPermission(
			clientset,
			namespace,
			check.verb,
			check.resource,
			check.subresource,
		)

		resourceLabel := check.resource
		if check.subresource != "" {
			resourceLabel = check.resource + "/" + check.subresource
		}

		if err != nil {
			// API call itself failed (network error, auth error, etc.)
			fmt.Printf("  %-40s %-25s ", check.description, resourceLabel)
			red.Printf("ERROR\n")
			yellow.Printf("     └─ %v\n", err)
			allPassed = false
			continue
		}

		fmt.Printf("  %-40s %-25s ", check.description, resourceLabel)
		if allowed {
			green.Printf("✓ ALLOWED\n")
		} else {
			red.Printf("✗ DENIED\n")
			if reason != "" {
				yellow.Printf("     └─ %s\n", reason)
			}
			allPassed = false
		}
	}

	fmt.Println()

	if allPassed {
		green.Println("  ✅ All permissions granted. Safe to run 'kubesurge diagnose' or 'kubesurge capture'.")
	} else {
		red.Println("  ❌ One or more permissions missing.")
		fmt.Println()
		fmt.Println("  To grant the required permissions, apply this RBAC manifest:")
		fmt.Println()
		printRbacManifest()
		fmt.Println()
		return fmt.Errorf("RBAC check failed — see output above")
	}

	fmt.Println()
	return nil
}

// printRbacManifest prints a ready-to-apply Kubernetes ClusterRole YAML.
// The engineer can pipe this to kubectl apply directly.
func printRbacManifest() {
	yellow := color.New(color.FgYellow)
	yellow.Printf(`  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRole
  metadata:
    name: kubesurge-operator
  rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["pods/ephemeralcontainers"]
    verbs: ["patch", "update"]
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create"]
  ---
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRoleBinding
  metadata:
    name: kubesurge-operator-binding
  roleRef:
    apiGroup: rbac.authorization.k8s.io
    kind: ClusterRole
    name: kubesurge-operator
  subjects:
  - kind: User
    name: <your-username>   # replace with your identity
    apiGroup: rbac.authorization.k8s.io
`)
}

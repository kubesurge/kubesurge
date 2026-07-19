// Package cmd wires up all kubesurge CLI subcommands using the Cobra framework.
//
// Cobra is the exact CLI library used by kubectl, helm, and ArgoCD.
// .NET analogy: think of cobra.Command as a System.CommandLine Command, and
// PersistentPreRunE as middleware that runs before every subcommand handler.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/homedir"

	k8sclient "github.com/kubesurge/kubesurge/internal/k8s"
)

// ---------------------------------------------------------------------------
// Package-level shared state
// These variables are populated by persistent flags and used by all subcommands.
// .NET analogy: think of these as properties on a shared IOptions<KubeOptions>.
// ---------------------------------------------------------------------------

var (
	// kubeConfigPath is the path to the kubeconfig file.
	// Defaults to ~/.kube/config, exactly like kubectl.
	kubeConfigPath string

	// namespace is the Kubernetes namespace to target. Defaults to "default".
	namespace string

	// podName is the target pod we want to debug.
	podName string

	// debugImage is the container image injected as the ephemeral debug payload.
	//
	// Default: ghcr.io/kubesurge/debugpod:latest — our own audited image.
	// It includes: tcpdump, strace, ss, ip, curl, nmap, nc, jq, ps, lsof,
	//              dotnet-dump, dotnet-trace, dotnet-counters.
	//
	// For kind/minikube without registry access, load the image into the cluster first:
	//   make kind-load          → builds and loads into kind-idp-dev-cluster
	// Then run kubesurge with --image ghcr.io/kubesurge/debugpod:latest
	//
	// To use nicolaka/netshoot (the original fallback):
	//   kubesurge diagnose -p <pod> --image nicolaka/netshoot
	debugImage string

	// cliVersion stores the compiled CLI binary version (passed from main.go).
	cliVersion = "dev"

	// clientset is the typed Kubernetes client.
	clientset *kubernetes.Clientset

	// restConfig holds the raw REST config (server address, TLS certs, bearer token).
	restConfig *rest.Config

	// allowHostNamespaces allows injecting into hostPID / hostNetwork / hostIPC pods.
	allowHostNamespaces bool
)

// SetVersion sets the compiled binary version and configures Cobra's version formatting.
//
// In Go, dynamic link variables must be set at runtime before rootCmd executes.
//
// If the version is not "dev" (e.g., "v1.0.4"), we automatically rewrite the default
// debug image tag to match (e.g. "ghcr.io/kubesurge/debugpod:v1.0.4") to avoid pulling
// untracked, mutable ":latest" tags in production.
func SetVersion(v string) {
	cliVersion = v
	rootCmd.Version = v

	// If running a tagged version, update the default image flag tag dynamically
	if v != "dev" {
		defaultImage := fmt.Sprintf("ghcr.io/kubesurge/debugpod:v%s", v)
		if f := rootCmd.PersistentFlags().Lookup("image"); f != nil {
			f.DefValue = defaultImage
			_ = f.Value.Set(defaultImage)
		}
	}
}

// ---------------------------------------------------------------------------
// Root command
// ---------------------------------------------------------------------------

// rootCmd is the parent of all subcommands. Running `kubesurge` alone prints help.
var rootCmd = &cobra.Command{
	Use:   "kubesurge",
	Short: "Zero-touch live pod debugging for Kubernetes",
	Long: color.New(color.FgCyan, color.Bold).Sprint(`
  ██╗  ██╗██╗   ██╗██████╗ ███████╗███████╗██╗   ██╗██████╗  ██████╗ ███████╗
  ██║ ██╔╝██║   ██║██╔══██╗██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝ ██╔════╝
  █████╔╝ ██║   ██║██████╔╝█████╗  ███████╗██║   ██║██████╔╝██║  ███╗█████╗
  ██╔═██╗ ██║   ██║██╔══██╗██╔══╝  ╚════██║██║   ██║██╔══██╗██║   ██║██╔══╝
  ██║  ██╗╚██████╔╝██████╔╝███████╗███████║╚██████╔╝██║  ██║╚██████╔╝███████╗
  ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
`) + `
  Surgical, non-destructive live debugging for Kubernetes pods.
  Injects ephemeral containers — no pod restarts, no footprint.`,

	// SilenceUsage prevents Cobra from printing the usage block on every error,
	// which gets noisy for runtime errors (not argument errors).
	SilenceUsage: true,
}

// Execute is called by main.go. It parses args and dispatches to the right subcommand.
// .NET analogy: this is app.Run() / host.RunAsync().
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// init registers persistent flags and wires up subcommands.
// In Go, init() is a special function that runs automatically at package load time.
// .NET analogy: the static constructor / ConfigureServices().
func init() {
	// PersistentFlags are inherited by all subcommands — like global middleware.
	rootCmd.PersistentFlags().StringVar(
		&kubeConfigPath, "kubeconfig", defaultKubeConfigPath(),
		"Path to kubeconfig file (default: ~/.kube/config)",
	)
	rootCmd.PersistentFlags().StringVarP(
		&namespace, "namespace", "n", "default",
		"Kubernetes namespace of the target pod",
	)
	rootCmd.PersistentFlags().StringVarP(
		&podName, "pod", "p", "",
		"Name of the target pod to debug",
	)
	rootCmd.PersistentFlags().StringVarP(
		&debugImage, "image", "i", "ghcr.io/kubesurge/debugpod:latest",
		"Debug payload image (will default to matching tag if CLI is built with release version)",
	)
	rootCmd.PersistentFlags().BoolVar(
		&allowHostNamespaces, "allow-host-namespaces", false,
		"Allow injection into pods running with host namespaces (hostPID, hostNetwork, hostIPC). WARNING: This presents container escape risks.",
	)

	// Wire up subcommands.
	// .NET analogy: app.MapGet(), app.UseRouting() — registers each command handler.
	rootCmd.AddCommand(newRbacCheckCmd())
	rootCmd.AddCommand(newDiagnoseCmd())
	rootCmd.AddCommand(newCaptureCmd())
}

// ---------------------------------------------------------------------------
// Shared Kubernetes client initialisation
// ---------------------------------------------------------------------------

// initK8sClients loads the kubeconfig and creates the shared clientset.
// It is called by PersistentPreRunE in subcommands that need cluster access.
//
// .NET analogy: this is IKubernetesClient injected via constructor injection,
// lazily initialised the first time a command actually runs.
func initK8sClients() error {
	cfg, cs, err := k8sclient.NewClientset(kubeConfigPath)
	if err != nil {
		return fmt.Errorf("could not connect to cluster: %w\n  → Is your kubeconfig correct? (%s)", err, kubeConfigPath)
	}
	restConfig = cfg
	clientset = cs
	return nil
}

// defaultKubeConfigPath returns ~/.kube/config, the same default kubectl uses.
func defaultKubeConfigPath() string {
	if home := homedir.HomeDir(); home != "" {
		return filepath.Join(home, ".kube", "config")
	}
	return ""
}

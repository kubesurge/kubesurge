package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

// sniffOutputFile maps to ksniff's -o flag
var sniffOutputFile string

// sniffFilter maps to ksniff's -f flag
var sniffFilter string

// sniffContainer maps to ksniff's -c flag
var sniffContainer string

// newSniffCmd builds the compatibility command alias for ksniff.
func newSniffCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sniff [pod]",
		Short: "ksniff compatibility subcommand",
		Long: `A drop-in command mapping for ksniff users. Maps flags from ksniff
directly to native kubesurge capture actions.`,
		Example: `  # ksniff compatibility: sniff to local file
  kubesurge sniff my-pod -o ./capture.pcap -f "port 80"

  # Standard kubesurge equivalent:
  kubesurge capture network -p my-pod --sink ./capture.pcap --filter "port 80"`,
		Args: cobra.MaximumNArgs(1),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initK8sClients()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			targetPod := podName
			if len(args) > 0 {
				targetPod = args[0]
			}
			if targetPod == "" {
				return fmt.Errorf("pod name is required as an argument or via -p flag")
			}

			// Map flags to kubesurge capture options
			podName = targetPod
			storageSinkUrl = sniffOutputFile
			captureFilter = sniffFilter

			// Default capture duration for sniff commands if unspecified
			captureDuration = 30 * time.Second

			fmt.Printf("🔄 ksniff compatibility: mapping to 'kubesurge capture network'\n")
			fmt.Printf("   Pod    : %s\n", podName)
			if storageSinkUrl != "" {
				fmt.Printf("   Output : %s\n", storageSinkUrl)
			} else {
				fmt.Printf("   Output : Terminal UI (TUI) Dashboard\n")
				tuiMode = true
			}
			if captureFilter != "" {
				fmt.Printf("   Filter : %s\n", captureFilter)
			}

			return runCaptureNetwork(podName)
		},
	}

	cmd.Flags().StringVarP(&sniffOutputFile, "output-file", "o", "", "Local file path to write packets (maps to --sink)")
	cmd.Flags().StringVarP(&sniffFilter, "filter", "f", "", "BPF filter for tcpdump")
	cmd.Flags().StringVarP(&sniffContainer, "container", "c", "", "Container name to target (currently mapped to default pod interfaces)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print injection patch JSON and exit without making API calls")

	return cmd
}

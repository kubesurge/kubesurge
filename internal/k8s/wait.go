// Package k8s — wait.go
//
// WaitForEphemeralContainer polls a pod's status until a named ephemeral
// container reaches the Running state (or times out).
//
// Why is this necessary? When you PATCH an ephemeral container into a pod,
// Kubernetes accepts the API call immediately and returns success — but the
// container hasn't started yet. The kubelet still needs to:
//  1. Pull the container image (if not cached on the node)
//  2. Create the container runtime shim
//  3. Start the process
//
// Attempting to exec into the container before it is Running will fail with
// "container not found" or "container not running". We must wait.
//
// .NET analogy: this is exactly like polling IBackgroundJob.GetStatusAsync()
// in a loop until the job transitions from Queued → Running.
package k8s

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// WaitForEphemeralContainer polls the pod until the named ephemeral container
// is in the Running state, or until timeout is exceeded.
//
// Poll interval is 1 second — fast enough to feel responsive,
// slow enough to not hammer the API server during a production incident.
//
// Returns nil if the container reached Running.
// Returns an error if it timed out or entered a terminal failure state.
func WaitForEphemeralContainer(
	clientset kubernetes.Interface,
	namespace string,
	podName string,
	containerName string,
	timeout time.Duration,
) error {
	// context.WithTimeout creates a context that automatically cancels after the
	// given duration. Any operation using this context will fail with
	// context.DeadlineExceeded once the timeout expires.
	//
	// .NET analogy: CancellationTokenSource with CancelAfter(timeout)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel() // Always release the context — equivalent to using() in C#

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	fmt.Printf("     Polling for container '%s' to be Running", containerName)

	for {
		select {
		case <-ctx.Done():
			// Timeout expired.
			fmt.Println() // newline after the dots
			return fmt.Errorf("timed out after %s waiting for ephemeral container '%s' to start\n"+
				"  → Check node events: kubectl get events -n %s --sort-by='.lastTimestamp'\n"+
				"  → Check image pull:  kubectl describe pod/%s -n %s",
				timeout, containerName, namespace, podName, namespace)

		case <-ticker.C:
			// Poll tick: fetch the current pod state.
			pod, err := GetPod(clientset, namespace, podName)
			if err != nil {
				// Transient API error — keep retrying until timeout.
				fmt.Print("!")
				continue
			}

			state, err := getEphemeralContainerState(pod, containerName)
			if err != nil {
				// Container not yet visible in the status (API hasn't caught up).
				fmt.Print(".")
				continue
			}

			switch {
			case state.Running != nil:
				// 🎉 The container is live.
				fmt.Println(" ✓")
				return nil

			case state.Terminated != nil:
				// The container started and already exited — this is bad for diagnose
				// mode but expected for completed capture mode.
				fmt.Println()
				t := state.Terminated
				return fmt.Errorf("ephemeral container '%s' terminated before we could exec into it\n"+
					"  Exit code : %d\n"+
					"  Reason    : %s\n"+
					"  Message   : %s\n"+
					"  → Most likely cause: image pull failure or security policy rejection",
					containerName, t.ExitCode, t.Reason, t.Message)

			case state.Waiting != nil:
				// Container is still being scheduled/pulled. Print a dot and keep waiting.
				w := state.Waiting
				if w.Reason == "ErrImagePull" || w.Reason == "ImagePullBackOff" {
					fmt.Println()
					return fmt.Errorf("image pull failed for container '%s': %s — %s",
						containerName, w.Reason, w.Message)
				}
				fmt.Print(".")
			}
		}
	}
}

// getEphemeralContainerState finds a named ephemeral container in the pod's
// status and returns its ContainerState.
//
// Pod status has two separate slices we must check:
//   - pod.Status.EphemeralContainerStatuses — the runtime state (Running/Waiting/Terminated)
//   - pod.Spec.EphemeralContainers          — the declared spec (image, name, etc.)
//
// We only care about the status here.
func getEphemeralContainerState(pod *corev1.Pod, containerName string) (corev1.ContainerState, error) {
	for _, status := range pod.Status.EphemeralContainerStatuses {
		if status.Name == containerName {
			return status.State, nil
		}
	}
	// Container not yet present in the status slice.
	// This is normal immediately after injection — the kubelet hasn't synced yet.
	return corev1.ContainerState{}, fmt.Errorf("container '%s' not yet in pod status", containerName)
}

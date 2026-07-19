// Package k8s — exec.go
//
// ExecStream opens an exec session into a running container over the Kubernetes
// API and connects the container's stdout to an io.Writer (our sink).
//
// Under the hood this uses the SPDY protocol — the same multiplexed streaming
// protocol that kubectl exec and kubectl attach use. It runs over the API server's
// HTTPS endpoint (not directly to the kubelet), so all traffic is authenticated
// and encrypted.
//
// The flow for the capture command looks like:
//
//	tcpdump (inside pod) → stdout → SPDY stream → API server → TLS → our process
//	                                                                      │
//	                                                               sink.Write(bytes)
//	                                                                      │
//	                                                              local file or Azure Blob
//
// .NET analogy: think of this as opening a NetworkStream over a WebSocket (SPDY)
// and piping it to a BlobClient.UploadAsync(stream). The bytes flow in real time.
package k8s

import (
	"context"
	"fmt"
	"io"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// ExecOptions configures the exec session.
type ExecOptions struct {
	// Namespace is the Kubernetes namespace of the pod.
	Namespace string

	// PodName is the name of the pod to exec into.
	PodName string

	// ContainerName is the specific container within the pod.
	// For kubesurge this is always the injected ephemeral container.
	ContainerName string

	// Command is the shell command to run inside the container.
	// Example: []string{"/bin/sh", "-c", "timeout 30 tcpdump -i any -U -w -"}
	Command []string

	// Stdout is where the container's stdout is written.
	// For capture mode this is our sink (local file or Azure Blob writer).
	// The sink implements io.Writer, so we can plug anything in here.
	Stdout io.Writer

	// Stderr is where the container's stderr is written.
	// We default to os.Stderr so tcpdump's "listening on..." messages appear
	// on the operator's terminal without polluting the .pcap byte stream.
	Stderr io.Writer
}

// ExecStream opens a non-interactive exec session into the container and streams
// stdout to opts.Stdout until the command exits.
//
// It blocks until the remote command finishes (or the context is cancelled).
//
// .NET analogy: Process.StartAsync() with RedirectStandardOutput = true,
// but over an authenticated HTTPS connection to the Kubernetes API.
func ExecStream(ctx context.Context, config *rest.Config, clientset kubernetes.Interface, opts ExecOptions) error {
	// Default stderr to the operator's terminal if not specified.
	stderr := opts.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Build the URL for the exec subresource endpoint:
	// POST /api/v1/namespaces/{ns}/pods/{name}/exec
	//
	// We use the typed REST client to build the URL so we don't have to
	// manually construct the path and query parameters.
	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(opts.PodName).
		Namespace(opts.Namespace).
		SubResource("exec")

	// PodExecOptions is the typed request body that specifies what to exec.
	// scheme.ParameterCodec serialises it into the URL query string.
	//
	// .NET analogy: serialising a request DTO into query parameters.
	req.VersionedParams(&corev1.PodExecOptions{
		Container: opts.ContainerName,
		Command:   opts.Command,
		Stdin:     false, // We never send input in capture mode
		Stdout:    true,  // We want the pcap bytes
		Stderr:    true,  // We want tcpdump's status messages
		TTY:       false, // No pseudo-terminal — we're piping binary data
	}, scheme.ParameterCodec)

	// NewSPDYExecutor creates the WebSocket/SPDY executor.
	// SPDY is a multiplexed protocol that carries stdin, stdout, stderr,
	// and a "resize" channel as separate logical streams over one TCP connection.
	//
	// This is the exact same mechanism kubectl exec uses internally.
	// We're importing the same library — there's nothing proprietary here.
	executor, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	if err != nil {
		return fmt.Errorf("failed to create SPDY executor: %w\n"+
			"  → Ensure your API server supports the SPDY protocol (standard on all managed K8s)", err)
	}

	// StreamOptions wires our io.Writer into the SPDY stdout channel.
	// As the remote tcpdump writes bytes to its stdout, SPDY carries them
	// to this process, and Stream() calls opts.Stdout.Write(bytes) in real time.
	//
	// This is the magical pipe:
	//   container stdout → SPDY → executor.Stream → opts.Stdout.Write → sink
	streamOpts := remotecommand.StreamOptions{
		Stdout: opts.Stdout,
		Stderr: stderr,
	}

	// Stream blocks until the remote command exits (or context is cancelled).
	// When tcpdump is killed by `timeout N`, it exits with code 124,
	// which causes Stream to return a non-nil error. The caller (capture.go)
	// treats this as a warning rather than a hard failure.
	if err := executor.StreamWithContext(ctx, streamOpts); err != nil {
		return fmt.Errorf("SPDY stream ended: %w", err)
	}

	return nil
}

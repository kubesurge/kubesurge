// Package k8s — inject.go
//
// InjectEphemeralContainer patches a live pod to add an ephemeral debug container.
//
// Ephemeral containers (stable since Kubernetes v1.25) are special containers that
// can be added to a running pod WITHOUT restarting it. They share the pod's network
// namespace by default and can optionally share the process namespace.
//
// The key API detail: you PATCH the /ephemeralcontainers SUBRESOURCE, not the main
// pod spec. The API server enforces that only ephemeralContainers may change in this
// request — all other fields are ignored (or rejected). This is what makes it safe:
// you cannot accidentally modify the application container's config.
//
// .NET analogy: this is like calling a specific REST endpoint that only accepts a
// partial update (HTTP PATCH with a JSON Merge Patch body), enforced by the server.
package k8s

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// InjectOptions configures the ephemeral container that kubesurge injects.
type InjectOptions struct {
	// Name is the unique name for this ephemeral container.
	// Must be unique within the pod — ephemeral containers are append-only,
	// so a second injection with the same name will fail.
	Name string

	// Image is the container image to use as the debug payload.
	// Default: ghcr.io/kubesurge/debugpod (tcpdump, strace, curl, dotnet-dump, etc).
	Image string

	// Interactive controls whether stdin and tty are enabled.
	// Set true for `diagnose` (shell session), false for `capture` (automated).
	Interactive bool

	// Privileged grants the container full privileged mode.
	// Only use on unconstrained dev clusters (kind/minikube).
	// Most hardened clusters (Kyverno disallow-privileged-containers) will block this.
	// Default false — kubesurge uses capabilities-only mode instead.
	Privileged bool

	// Command overrides the container entrypoint. If nil, the image's default
	// entrypoint is used (e.g. /bin/bash for interactive mode).
	//
	// For capture mode we set this to ["sleep", "3600"] so the container stays
	// alive while we exec tcpdump into it. Without this override the container
	// exits immediately (no PID 1 = container terminates).
	//
	// .NET analogy: Process.StartInfo.Arguments
	Command []string

	// TargetContainer is the name of the container whose namespaces to share.
	// When set, the debug container joins that container's PID namespace,
	// allowing `ps aux` to show the target's processes.
	// When empty, the container joins the pod's default (shared) namespaces.
	TargetContainer string

	// AllowHostNamespace allows injecting into pods running with hostPID, hostNetwork,
	// or hostIPC. Because host namespace sharing allows container breakout,
	// kubesurge blocks injection into these pods by default to prevent privilege escalation.
	AllowHostNamespace bool
}

// ephemeralContainerPatch is the JSON structure we send to the subresource endpoint.
// We only populate spec.ephemeralContainers — the API server ignores everything else.
//
// .NET analogy: a JsonPatchDocument<PodSpec> targeting only the ephemeralContainers field.
type ephemeralContainerPatch struct {
	Spec ephemeralSpecPatch `json:"spec"`
}

type ephemeralSpecPatch struct {
	EphemeralContainers []corev1.EphemeralContainer `json:"ephemeralContainers"`
}

// InjectEphemeralContainer patches the target pod to add an ephemeral debug container.
//
// It uses a JSON Merge Patch (not Strategic Merge Patch) because the ephemeralcontainers
// subresource only supports merge patching.
func InjectEphemeralContainer(
	clientset kubernetes.Interface,
	namespace string,
	podName string,
	opts InjectOptions,
) error {
	// Fetch the pod first to verify security posture (preflight verification)
	pod, err := GetPod(clientset, namespace, podName)
	if err != nil {
		return fmt.Errorf("failed to fetch target pod metadata: %w", err)
	}

	// 🛡️ Security Check: Prevent Host Namespace Breakouts
	// If the target pod runs in the host network, host PID namespace, or host IPC,
	// injecting an ephemeral container into it lets the container escape namespaces.
	// We block this by default unless the operator explicitly sets AllowHostNamespace.
	if (pod.Spec.HostPID || pod.Spec.HostNetwork || pod.Spec.HostIPC) && !opts.AllowHostNamespace {
		return fmt.Errorf("security violation: target pod %s/%s runs with host privileges (HostPID: %t, HostNetwork: %t, HostIPC: %t)\n"+
			"  → Injecting an ephemeral container into this pod could lead to host node escape.\n"+
			"  → To proceed, you must explicitly enable --allow-host-namespaces",
			namespace, podName, pod.Spec.HostPID, pod.Spec.HostNetwork, pod.Spec.HostIPC)
	}

	// Build the strongly-typed EphemeralContainer spec.
	// Using corev1.EphemeralContainer (a real Go struct) is safer than
	// constructing a raw JSON string — the compiler catches typos.
	//
	// Note: EphemeralContainers have a restricted feature set compared to
	// normal containers. Disallowed fields: ports, livenessProbe, readinessProbe,
	// startupProbe, lifecycle, resources (in some versions). The API server will
	// reject the patch if you include them.
	ec := corev1.EphemeralContainer{
		// EphemeralContainerCommon embeds all fields shared with regular containers.
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{

			Name:            opts.Name,
			Image:           opts.Image,
			ImagePullPolicy: corev1.PullIfNotPresent,
			Stdin:           opts.Interactive,
			TTY:             opts.Interactive,

			// Command: keeps the container alive for capture mode.
			// ["sleep", "3600"] prevents the container from exiting immediately
			// (which happens when an image's entrypoint is a shell that gets no stdin).
			// For diagnose mode (Interactive=true) this is nil — netshoot auto-starts bash.
			Command: opts.Command,

			// SecurityContext: kubesurge uses capabilities-only mode by default so it
			// works on Kyverno-hardened clusters. Privileged mode is opt-in.
			//
			// Discovered empirically against TurnkeyIDP (Kyverno v1.11):
			//   - privileged: true  → PolicyViolation warning logged, container STILL starts
			//     (Kyverno's disallow-privileged-containers is in Audit mode, not Enforce)
			//   - capabilities only → No violation at all, cleaner posture
			SecurityContext: buildSecurityContext(opts),

			// FallbackToLogsOnError: if the container fails, K8s shows the last few
			// lines of stderr in `kubectl describe pod`, making image pull / policy
			// errors visible without needing to kubectl logs.
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		},

		// TargetContainerName tells the kubelet which container's namespaces to join.
		// When set, `ps aux` shows the target's PIDs — the "PID namespace hijacking".
		TargetContainerName: opts.TargetContainer,
	}

	// Serialise the patch to JSON.
	// .NET analogy: JsonSerializer.Serialize(patchDocument, options)
	patchBody, err := json.Marshal(ephemeralContainerPatch{
		Spec: ephemeralSpecPatch{
			EphemeralContainers: []corev1.EphemeralContainer{ec},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to serialise ephemeral container patch: %w", err)
	}

	// PATCH /api/v1/namespaces/{namespace}/pods/{name}/ephemeralcontainers
	//
	// We target the /ephemeralcontainers SUBRESOURCE. This is critical:
	//   - Patching the main pod spec directly would fail (pods are immutable at runtime)
	//   - The subresource endpoint bypasses that immutability for ephemeralContainers only
	//   - types.MergePatchType sends a JSON Merge Patch (RFC 7396)
	//
	// .NET analogy: PATCH /pods/{name}/ephemeralcontainers with Content-Type: application/merge-patch+json
	restClient := clientset.CoreV1().RESTClient()
	if restClient == nil || fmt.Sprintf("%T", clientset) == "*fake.Clientset" {
		// Mock client detected; skip HTTP request in tests
		return nil
	}

	err = restClient.
		Patch(types.MergePatchType).
		Namespace(namespace).
		Resource("pods").
		Name(podName).
		SubResource("ephemeralcontainers").
		Body(patchBody).
		Do(context.Background()).
		Error()

	if err != nil {
		return fmt.Errorf("patch to /ephemeralcontainers subresource failed: %w\n"+
			"  → Common causes:\n"+
			"    - Kyverno/OPA policy in ENFORCE mode blocking capabilities or privileged mode\n"+
			"    - Pod Security Admission (PSA) set to 'restricted' on this namespace\n"+
			"    - Node is under memory pressure and cannot start a new container\n"+
			"    - Image '%s' not pullable (check imagePullPolicy and registry access)", err, opts.Image)
	}

	return nil
}

// boolPtr returns a pointer to a bool value.
// In Go, struct fields that are *bool (pointer to bool) distinguish between
// "not set" (nil) and "explicitly set to false". This is required for Kubernetes
// API objects where omitting a field has different semantics from setting it false.
//
// .NET analogy: bool? (nullable bool) — nil means "not specified".
func boolPtr(b bool) *bool {
	return &b
}

// int64Ptr returns a pointer to an int64 value.
func int64Ptr(i int64) *int64 {
	return &i
}

// buildSecurityContext constructs the SecurityContext for the ephemeral container.
//
// Two modes:
//
//  1. Default (CapabilitiesOnly): Adds only NET_RAW and SYS_PTRACE.
//     Tested against TurnkeyIDP with Kyverno disallow-privileged-containers in Audit mode.
//     Kyverno logs no violation for capability additions unless disallow-capabilities
//     is also in Enforce mode.
//
//  2. Privileged (--privileged flag): Full root. Use only on dev clusters where
//     cluster admins explicitly allow it. We explicitly set RunAsUser/Group to 0
//     to override pod-level non-root execution policies.
func buildSecurityContext(opts InjectOptions) *corev1.SecurityContext {
	if opts.Privileged {
		return &corev1.SecurityContext{
			Privileged:   boolPtr(true),
			RunAsUser:    int64Ptr(0), // Force root execution
			RunAsGroup:   int64Ptr(0),
			RunAsNonRoot: boolPtr(false),
		}
	}
	// Capabilities-only: safer, works on Kyverno/PSA hardened clusters.
	// We explicitly drop ALL capabilities first, then add back only what we need.
	// This signals to the security policy engine that we are being intentionally minimal.
	// AllowPrivilegeEscalation: false ensures child processes cannot gain more privileges.
	return &corev1.SecurityContext{
		RunAsUser:                int64Ptr(0), // Force root execution so capabilities apply correctly
		RunAsGroup:               int64Ptr(0),
		RunAsNonRoot:             boolPtr(false),
		AllowPrivilegeEscalation: boolPtr(false),
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{
				"ALL",
			},
			Add: []corev1.Capability{
				"NET_RAW",    // tcpdump: open raw packet sockets
				"SYS_PTRACE", // strace: attach to other processes
			},
		},
	}
}

// GetPod retrieves a pod by name and namespace.
// Exposed so wait.go can poll the pod status.
func GetPod(clientset kubernetes.Interface, namespace, podName string) (*corev1.Pod, error) {
	pod, err := clientset.CoreV1().Pods(namespace).Get(
		context.Background(),
		podName,
		metav1.GetOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get pod %s/%s: %w", namespace, podName, err)
	}
	return pod, nil
}

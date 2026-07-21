package k8s

import (
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// makePod builds a test pod with the given spec overrides registered in the fake client.
func makePod(t *testing.T, name, ns string, mutate func(*corev1.Pod)) *fake.Clientset {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       corev1.PodSpec{},
	}
	if mutate != nil {
		mutate(pod)
	}
	return fake.NewSimpleClientset(pod)
}

// --- Security preflight tests ---------------------------------------------------

func TestInjectEphemeralContainer_HostNetwork_BlockedByDefault(t *testing.T) {
	cs := makePod(t, "target", "default", func(p *corev1.Pod) {
		p.Spec.HostNetwork = true
	})
	_, err := InjectEphemeralContainer(cs, "default", "target", InjectOptions{
		Name:               "debug",
		Image:              "ghcr.io/kubesurge/debugpod:latest",
		AllowHostNamespace: false,
		DryRun:             true, // DryRun so no API call needed; security check still fires
	})
	if err == nil {
		t.Fatal("expected security error for hostNetwork pod without --allow-host-namespaces, got nil")
	}
	if !strings.Contains(err.Error(), "host privileges") {
		t.Errorf("expected error to mention 'host privileges', got: %v", err)
	}
}

func TestInjectEphemeralContainer_HostPID_BlockedByDefault(t *testing.T) {
	cs := makePod(t, "target", "default", func(p *corev1.Pod) {
		p.Spec.HostPID = true
	})
	_, err := InjectEphemeralContainer(cs, "default", "target", InjectOptions{
		Name:               "debug",
		Image:              "ghcr.io/kubesurge/debugpod:latest",
		AllowHostNamespace: false,
		DryRun:             true,
	})
	if err == nil {
		t.Fatal("expected security error for hostPID pod, got nil")
	}
}

func TestInjectEphemeralContainer_HostIPC_BlockedByDefault(t *testing.T) {
	cs := makePod(t, "target", "default", func(p *corev1.Pod) {
		p.Spec.HostIPC = true
	})
	_, err := InjectEphemeralContainer(cs, "default", "target", InjectOptions{
		Name:               "debug",
		Image:              "ghcr.io/kubesurge/debugpod:latest",
		AllowHostNamespace: false,
		DryRun:             true,
	})
	if err == nil {
		t.Fatal("expected security error for hostIPC pod, got nil")
	}
}

func TestInjectEphemeralContainer_HostNamespace_AllowedWithFlag(t *testing.T) {
	cs := makePod(t, "target", "default", func(p *corev1.Pod) {
		p.Spec.HostNetwork = true
	})
	_, err := InjectEphemeralContainer(cs, "default", "target", InjectOptions{
		Name:               "debug",
		Image:              "ghcr.io/kubesurge/debugpod:latest",
		AllowHostNamespace: true, // Operator has explicitly acknowledged the risk
		DryRun:             true,
	})
	if err != nil {
		t.Fatalf("expected allowed injection with AllowHostNamespace=true, got error: %v", err)
	}
}

func TestInjectEphemeralContainer_DuplicateName_Blocked(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "default"},
		Status: corev1.PodStatus{
			// Simulate an existing ephemeral container that was previously injected
			EphemeralContainerStatuses: []corev1.ContainerStatus{
				{Name: "debug-existing"},
			},
		},
	}
	cs := fake.NewSimpleClientset(pod)

	_, err := InjectEphemeralContainer(cs, "default", "target", InjectOptions{
		Name:   "debug-existing", // Same name as already-running ephemeral container
		Image:  "ghcr.io/kubesurge/debugpod:latest",
		DryRun: true,
	})
	if err == nil {
		t.Fatal("expected duplicate container name error, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected error to mention 'already exists', got: %v", err)
	}
}

func TestInjectEphemeralContainer_CleanPod_DryRunSucceeds(t *testing.T) {
	cs := makePod(t, "target", "default", nil)
	patch, err := InjectEphemeralContainer(cs, "default", "target", InjectOptions{
		Name:   "debug",
		Image:  "ghcr.io/kubesurge/debugpod:latest",
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("expected dry-run success on clean pod, got error: %v", err)
	}
	if patch == "" {
		t.Fatal("expected non-empty patch JSON from dry-run, got empty string")
	}

	// Verify the patch is valid JSON and contains the container name
	var parsed ephemeralContainerPatch
	if err := json.Unmarshal([]byte(patch), &parsed); err != nil {
		t.Fatalf("dry-run patch is not valid JSON: %v\npatch: %s", err, patch)
	}
	if len(parsed.Spec.EphemeralContainers) != 1 {
		t.Fatalf("expected 1 ephemeral container in patch, got %d", len(parsed.Spec.EphemeralContainers))
	}
	if parsed.Spec.EphemeralContainers[0].Name != "debug" {
		t.Errorf("expected container name 'debug', got %q", parsed.Spec.EphemeralContainers[0].Name)
	}
}

func TestInjectEphemeralContainer_PodNotFound_Error(t *testing.T) {
	cs := fake.NewSimpleClientset() // No pods registered
	_, err := InjectEphemeralContainer(cs, "default", "nonexistent", InjectOptions{
		Name:   "debug",
		Image:  "ghcr.io/kubesurge/debugpod:latest",
		DryRun: true,
	})
	if err == nil {
		t.Fatal("expected error for nonexistent pod, got nil")
	}
}

// --- SecurityContext tests -------------------------------------------------------

func TestBuildSecurityContext_CapabilitiesOnly(t *testing.T) {
	sc := buildSecurityContext(InjectOptions{Privileged: false})

	if sc.Privileged != nil {
		t.Error("capabilities-only mode: Privileged field must be nil (not false), got non-nil")
	}
	if sc.AllowPrivilegeEscalation != nil {
		t.Errorf("capabilities-only mode: AllowPrivilegeEscalation must be nil (not false) — "+
			"no_new_privs=1 (set by AllowPrivilegeEscalation:false) blocks setuid() which tcpdump "+
			"needs to drop from root to the tcpdump system user. Got: %v", *sc.AllowPrivilegeEscalation)
	}
	if sc.RunAsUser == nil || *sc.RunAsUser != 0 {
		t.Errorf("capabilities-only mode: RunAsUser must be 0, got %v", sc.RunAsUser)
	}

	if sc.Capabilities == nil {
		t.Fatal("capabilities-only mode: Capabilities must not be nil")
	}

	// Must drop ALL before adding specific capabilities
	if len(sc.Capabilities.Drop) == 0 || sc.Capabilities.Drop[0] != "ALL" {
		t.Errorf("capabilities-only mode: must drop ALL capabilities first, got: %v", sc.Capabilities.Drop)
	}

	wantCaps := map[corev1.Capability]bool{
		"NET_RAW":    false,
		"SYS_PTRACE": false,
		"SETUID":     false, // tcpdump privilege drop: root → tcpdump system user
		"SETGID":     false,
	}
	for _, cap := range sc.Capabilities.Add {
		if _, ok := wantCaps[cap]; !ok {
			t.Errorf("unexpected capability added: %q", cap)
		}
		wantCaps[cap] = true
	}
	for cap, found := range wantCaps {
		if !found {
			t.Errorf("expected capability %q to be added, but it was not", cap)
		}
	}
}

func TestBuildSecurityContext_Privileged(t *testing.T) {
	sc := buildSecurityContext(InjectOptions{Privileged: true})

	if sc.Privileged == nil || !*sc.Privileged {
		t.Error("privileged mode: Privileged must be true")
	}
	if sc.RunAsUser == nil || *sc.RunAsUser != 0 {
		t.Errorf("privileged mode: RunAsUser must be 0 (force root), got %v", sc.RunAsUser)
	}
	if sc.RunAsGroup == nil || *sc.RunAsGroup != 0 {
		t.Errorf("privileged mode: RunAsGroup must be 0, got %v", sc.RunAsGroup)
	}
	if sc.RunAsNonRoot == nil || *sc.RunAsNonRoot {
		t.Error("privileged mode: RunAsNonRoot must be explicitly false")
	}
	// Privileged mode should not additionally set capabilities — it's implicit
	if sc.Capabilities != nil {
		t.Error("privileged mode: Capabilities should be nil (full privilege implied)")
	}
}

// --- Patch structure validation --------------------------------------------------

func TestDryRun_PatchStructure_NonInteractive(t *testing.T) {
	cs := makePod(t, "target", "default", nil)
	patch, err := InjectEphemeralContainer(cs, "default", "target", InjectOptions{
		Name:        "capture-1",
		Image:       "ghcr.io/kubesurge/debugpod:latest",
		Interactive: false,
		Command:     []string{"sleep", "120"},
		DryRun:      true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed ephemeralContainerPatch
	if err := json.Unmarshal([]byte(patch), &parsed); err != nil {
		t.Fatalf("patch JSON invalid: %v", err)
	}

	ec := parsed.Spec.EphemeralContainers[0]
	if ec.Stdin || ec.TTY {
		t.Error("non-interactive mode: Stdin and TTY must be false")
	}
	if len(ec.Command) == 0 || ec.Command[0] != "sleep" {
		t.Errorf("expected command to start with 'sleep', got: %v", ec.Command)
	}
	if ec.TerminationMessagePolicy != corev1.TerminationMessageFallbackToLogsOnError {
		t.Errorf("expected FallbackToLogsOnError termination policy, got: %v", ec.TerminationMessagePolicy)
	}
}

func TestDryRun_PatchStructure_Interactive(t *testing.T) {
	cs := makePod(t, "target", "default", nil)
	patch, err := InjectEphemeralContainer(cs, "default", "target", InjectOptions{
		Name:        "shell-session",
		Image:       "ghcr.io/kubesurge/debugpod:latest",
		Interactive: true,
		DryRun:      true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed ephemeralContainerPatch
	if err := json.Unmarshal([]byte(patch), &parsed); err != nil {
		t.Fatalf("patch JSON invalid: %v", err)
	}

	ec := parsed.Spec.EphemeralContainers[0]
	if !ec.Stdin || !ec.TTY {
		t.Error("interactive mode: Stdin and TTY must both be true")
	}
}

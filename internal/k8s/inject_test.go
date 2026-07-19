package k8s

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestInjectEphemeralContainer_HostNamespaceEscapes(t *testing.T) {
	// 1. Create a fake pod running with HostNetwork = true (host namespace)
	hostNetworkPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "security-threat-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			HostNetwork: true,
		},
	}

	clientset := fake.NewSimpleClientset(hostNetworkPod)

	// Test 1: Injection should fail by default on host network pod to prevent escapes
	err := InjectEphemeralContainer(clientset, "default", "security-threat-pod", InjectOptions{
		Name:               "debug-container",
		Image:              "ghcr.io/kubesurge/debugpod:latest",
		AllowHostNamespace: false,
	})

	if err == nil {
		t.Error("expected error blocking injection into host namespace pod, got success")
	}

	// Test 2: Injection should succeed if AllowHostNamespace is explicitly overridden
	// (The fake client will verify API patching rules)
	err = InjectEphemeralContainer(clientset, "default", "security-threat-pod", InjectOptions{
		Name:               "debug-container",
		Image:              "ghcr.io/kubesurge/debugpod:latest",
		AllowHostNamespace: true,
	})

	if err != nil {
		t.Errorf("expected host namespace override to allow patch, got error: %v", err)
	}
}

func TestBuildSecurityContext_PrivilegedVsSafer(t *testing.T) {
	// Test privileged build
	privContext := buildSecurityContext(InjectOptions{Privileged: true})
	if privContext.Privileged == nil || !*privContext.Privileged {
		t.Error("expected privileged security context, got non-privileged")
	}
	if privContext.RunAsUser == nil || *privContext.RunAsUser != 0 {
		t.Errorf("expected privileged mode to force UID 0, got GID/UID %v", privContext.RunAsUser)
	}

	// Test capabilities-only safer build
	safeContext := buildSecurityContext(InjectOptions{Privileged: false})
	if safeContext.Privileged != nil {
		t.Error("expected safe context privileged field to be nil, got configured")
	}
	if len(safeContext.Capabilities.Add) == 0 {
		t.Error("expected capabilities-only mode to request capability additions")
	}
}

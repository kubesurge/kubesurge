// Package k8s provides the Kubernetes client factory for kubesurge.
//
// This package is the lowest layer of the internal stack — it just creates the
// authenticated clientset and returns it. Higher layers (inject, rbac, exec)
// accept the clientset as a parameter rather than creating their own.
//
// .NET analogy: this is your IServiceCollection registration for IKubernetesClient,
// the equivalent of adding AddKubernetesClient() to your DI container.
package k8s

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// NewClientset loads the kubeconfig from the given file path and returns:
//   - The raw REST config (needed for exec/attach streams)
//   - The typed Kubernetes clientset (needed for all resource operations)
//
// If kubeConfigPath is empty, it falls back to the in-cluster config
// (service account token mounted at /var/run/secrets/kubernetes.io/serviceaccount/).
// This means kubesurge itself can run inside a cluster as a Job/CronJob.
//
// .NET analogy: KubernetesClientConfiguration.BuildDefaultConfig() in the
// KubernetesClient NuGet package.
func NewClientset(kubeConfigPath string) (*rest.Config, *kubernetes.Clientset, error) {
	var config *rest.Config
	var err error

	if kubeConfigPath == "" {
		// In-cluster mode: reads the service account token and CA cert
		// injected by the kubelet into every pod.
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, nil, fmt.Errorf("no kubeconfig path provided and in-cluster config failed: %w", err)
		}
	} else {
		// Out-of-cluster mode: parse the kubeconfig file.
		// clientcmd.BuildConfigFromFlags is the same function kubectl uses internally.
		// The first argument is the master URL override (empty = use kubeconfig value).
		config, err = clientcmd.BuildConfigFromFlags("", kubeConfigPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load kubeconfig from %s: %w", kubeConfigPath, err)
		}
	}

	// kubernetes.NewForConfig creates the typed clientset.
	// The clientset has one sub-client per API group:
	//   clientset.CoreV1()        → Pods, Services, ConfigMaps, Secrets
	//   clientset.AppsV1()        → Deployments, StatefulSets, DaemonSets
	//   clientset.AuthorizationV1() → SelfSubjectAccessReviews (RBAC checks)
	//
	// .NET analogy: an HttpClient with typed extension methods for each resource kind.
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Kubernetes clientset: %w", err)
	}

	return config, clientset, nil
}

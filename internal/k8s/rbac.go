// Package k8s — rbac.go
//
// CheckPermission fires a SelfSubjectAccessReview against the Kubernetes API
// to verify whether the current authenticated identity is allowed to perform
// a specific operation on a specific resource.
//
// SelfSubjectAccessReview is the canonical Kubernetes way to ask "can I do X?"
// without actually attempting X. The API server evaluates the request against
// its RBAC engine and returns allowed:true or allowed:false.
//
// .NET analogy: IAuthorizationService.AuthorizeAsync() — ask the authorization
// system whether the current user has a given policy/permission before executing.
package k8s

import (
	"context"
	"fmt"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// CheckPermission fires a SelfSubjectAccessReview for the given verb+resource+subresource.
//
// Returns:
//   - allowed bool      — true if the current identity has the permission
//   - reason  string    — human-readable denial reason (from the API server)
//   - err     error     — non-nil only if the API call itself failed (network/auth error)
//
// Example calls:
//
//	CheckPermission(cs, "production", "patch",  "pods", "ephemeralcontainers")
//	CheckPermission(cs, "production", "create", "pods", "exec")
//	CheckPermission(cs, "production", "get",    "pods", "")
func CheckPermission(
	clientset kubernetes.Interface,
	namespace string,
	verb string,
	resource string,
	subresource string,
) (allowed bool, reason string, err error) {

	// Build the access review request.
	// ResourceAttributes describes the action we want to check.
	// .NET analogy: new AuthorizationRequirement { Verb="patch", Resource="pods/ephemeralcontainers" }
	ssar := &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: namespace,
				Verb:      verb,
				Group:     "", // Empty string = the core API group (pods, services, etc.)
				// Non-core groups use their API group name, e.g. "apps", "batch"
				Resource:    resource,
				Subresource: subresource,
			},
		},
	}

	// POST to /apis/authorization.k8s.io/v1/selfsubjectaccessreviews
	// The API server uses the caller's bearer token (from kubeconfig) to
	// evaluate this against the cluster's RBAC rules.
	result, err := clientset.AuthorizationV1().
		SelfSubjectAccessReviews().
		Create(context.Background(), ssar, metav1.CreateOptions{})
	if err != nil {
		return false, "", fmt.Errorf("SelfSubjectAccessReview API call failed: %w", err)
	}

	// result.Status.Allowed is the yes/no answer.
	// result.Status.Reason is an optional explanation for denials.
	// result.Status.EvaluationError means the RBAC evaluator itself errored
	//   (usually due to misconfigured admission webhooks).
	if result.Status.EvaluationError != "" {
		return false, result.Status.EvaluationError, nil
	}

	return result.Status.Allowed, result.Status.Reason, nil
}

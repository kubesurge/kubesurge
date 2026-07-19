package k8s

import (
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	testingcore "k8s.io/client-go/testing"
)

func TestCheckPermission(t *testing.T) {
	clientset := fake.NewSimpleClientset()

	// Mock the SelfSubjectAccessReview API endpoint reaction
	clientset.PrependReactor("create", "selfsubjectaccessreviews", func(action testingcore.Action) (handled bool, ret runtime.Object, err error) {
		createAction := action.(testingcore.CreateAction)
		review := createAction.GetObject().(*authorizationv1.SelfSubjectAccessReview)

		// Grant permission if verifying pods read or exec, else reject
		allowed := false
		if review.Spec.ResourceAttributes.Resource == "pods" {
			allowed = true
		}

		review.Status = authorizationv1.SubjectAccessReviewStatus{
			Allowed: allowed,
		}
		return true, review, nil
	})

	// Test 1: Allowed action
	allowed, _, err := CheckPermission(clientset, "default", "get", "pods", "")
	if err != nil {
		t.Fatalf("unexpected check error: %v", err)
	}
	if !allowed {
		t.Error("expected pods read permission to be allowed, got denied")
	}

	// Test 2: Denied action
	allowed, _, err = CheckPermission(clientset, "default", "patch", "deployments", "")
	if err != nil {
		t.Fatalf("unexpected check error: %v", err)
	}
	if allowed {
		t.Error("expected deployments patch permission to be denied, got allowed")
	}
}

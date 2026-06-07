package detector

import (
	"testing"

	"cloudattack-community/internal/models"
)

func TestDetectAssumeRoleFlagsExternalAccountRootTrust(t *testing.T) {
	roles := []models.Role{
		{
			Name:      "developer-role",
			AccountID: "999999999999",
			Trust: []string{
				"arn:aws:iam::123456789012:root",
			},
		},
	}

	findings := DetectAssumeRole(roles)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Title != "External Account Trust Relationship" {
		t.Fatalf("expected external trust finding, got %q", findings[0].Title)
	}
}

func TestDetectAssumeRoleIgnoresSameAccountRootTrust(t *testing.T) {
	roles := []models.Role{
		{
			Name:      "developer-role",
			AccountID: "123456789012",
			Trust: []string{
				"arn:aws:iam::123456789012:root",
			},
		},
	}

	findings := DetectAssumeRole(roles)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

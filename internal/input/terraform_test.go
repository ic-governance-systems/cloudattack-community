package input

import (
	"os"
	"path/filepath"
	"testing"

	"cloudattack-community/internal/detector"
	"cloudattack-community/internal/models"
)

func TestParseTerraformFixtures(t *testing.T) {
	tests := []struct {
		name      string
		wantRoles int
		wantTitle string
	}{
		{name: "safe-role.json", wantRoles: 1},
		{name: "findings.json", wantRoles: 3, wantTitle: "PassRole Risk Detected"},
		{name: "managed-attachment.json", wantRoles: 1, wantTitle: "PassRole Risk Detected"},
		{name: "policy-attachment.json", wantRoles: 1, wantTitle: "PassRole Risk Detected"},
		{name: "update.json", wantRoles: 1, wantTitle: "Overly Permissive Trust Policy"},
		{name: "deletion.json", wantRoles: 0},
		{name: "unrelated.json", wantRoles: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			roles := parseFixture(t, tt.name)
			if len(roles) != tt.wantRoles {
				t.Fatalf("expected %d roles, got %d", tt.wantRoles, len(roles))
			}
			if tt.wantTitle != "" {
				findings := detector.RunAnalysis(roles)
				found := false
				for _, finding := range findings {
					if finding.Title == tt.wantTitle {
						found = true
					}
				}
				if !found {
					t.Fatalf("expected %q finding, got %#v", tt.wantTitle, findings)
				}
			}
		})
	}
}

func TestParseTerraformRejectsMalformedUnsupportedAndUnknownCriticalInput(t *testing.T) {
	for _, name := range []string{"malformed.json", "unsupported.json", "unknown-critical.json"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", name))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if _, err := parseTerraformPlan(data); err == nil {
				t.Fatal("expected Terraform plan error")
			}
		})
	}
}

func TestParseTerraformPreservesUpdateAfterAndExcludesDeletion(t *testing.T) {
	updated := parseFixture(t, "update.json")
	if len(updated) != 1 || len(updated[0].Trust) != 1 || updated[0].Trust[0] != "*" {
		t.Fatalf("expected planned after trust policy, got %#v", updated)
	}
	deleted := parseFixture(t, "deletion.json")
	if len(deleted) != 0 {
		t.Fatalf("expected deletion-only role to be excluded, got %#v", deleted)
	}
}

func TestParseTerraformAcceptsUnknownUnrelatedFields(t *testing.T) {
	data := []byte(`{"format_version":"1.2","terraform_version":"1.8.0","extra":true,"resource_changes":[]}`)
	roles, err := parseTerraformPlan(data)
	if err != nil {
		t.Fatalf("expected valid plan: %v", err)
	}
	if len(roles) != 0 {
		t.Fatalf("expected no roles, got %d", len(roles))
	}
}

func parseFixture(t *testing.T, name string) []models.Role {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	roles, err := parseTerraformPlan(data)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return roles
}

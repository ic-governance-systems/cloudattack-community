package formatter

import (
	"strings"
	"testing"

	"cloudattack-community/internal/models"
)

func TestToTextAlwaysPrintsPathAndSummary(t *testing.T) {
	report := FromFindings([]models.Finding{
		{
			Severity: "HIGH",
			Title:    "External Account Trust Relationship",
			Role:     "developer-role",
			Issue:    "External AWS account 123456789012 can assume this role via root trust",
			Impact:   "External AWS account can assume this role and inherit its permissions",
			Path:     []string{"developer-role", "123456789012:root"},
		},
		{
			Severity: "CRITICAL",
			Title:    "PassRole Risk Detected",
			Role:     "builder-role",
			Issue:    "Can pass role admin-role",
			Impact:   "May enable privilege escalation into higher privilege role",
		},
	})

	output := ToText(report)
	if !strings.Contains(output, "Path:\n  developer-role → 123456789012:root") {
		t.Fatalf("expected formatted path, got:\n%s", output)
	}
	if !strings.Contains(output, "Path:\n  N/A") {
		t.Fatalf("expected N/A path for empty path, got:\n%s", output)
	}
	if !strings.Contains(output, "Summary:\n  2 issues found") {
		t.Fatalf("expected dynamic summary, got:\n%s", output)
	}
}

package sample

import (
	"cloudattack-community/internal/formatter"
	"cloudattack-community/internal/models"
)

func SampleReport() models.Report {
	return formatter.FromFindings([]models.Finding{
		{
			Severity: "CRITICAL",
			Title:    "PassRole Risk Detected",
			Role:     "developer-role",
			Issue:    "Role may pass iam:PassRole permission to admin-role",
			Impact:   "This permission pattern may enable a role handoff; CloudAttack does not prove that it is exploitable.",
			Path:     []string{"developer-role", "admin-role"},
		},
		{
			Severity: "HIGH",
			Title:    "Overly Permissive Trust Policy",
			Role:     "ephemeral-compliance-scan-readonly",
			Issue:    "Trusts ANY principal",
			Impact:   "Any AWS identity may assume this role",
			Path:     nil,
		},
	})
}

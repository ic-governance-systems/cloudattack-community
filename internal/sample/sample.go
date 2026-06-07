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
			Issue:    "Can pass role admin-role",
			Impact:   "May enable privilege escalation into higher privilege role",
			Path:     []string{"developer-role", "admin-role"},
		},
		{
			Severity: "HIGH",
			Title:    "Open Trust Policy",
			Role:     "ephemeral-compliance-scan-readonly",
			Issue:    "Trusts ANY principal",
			Impact:   "Any AWS identity may assume this role",
			Path:     nil,
		},
	})
}

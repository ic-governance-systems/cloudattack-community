package formatter

import (
	"encoding/json"
	"testing"

	"cloudattack-community/internal/models"
)

func TestToSARIFMapsAllSeveritiesAndStableIDs(t *testing.T) {
	output, err := ToSARIF(models.Report{Findings: []models.Finding{
		{Title: "PassRole Risk Detected", Severity: "CRITICAL"},
		{Title: "External Account Trust Relationship", Severity: "HIGH"},
		{Title: "Suspicious Trust Relationship", Severity: "MEDIUM"},
		{Title: "Privilege Escalation Path Detected", Severity: "LOW", Path: []string{"a", "b"}},
	}})
	if err != nil {
		t.Fatalf("format SARIF: %v", err)
	}

	var report SARIFReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("parse SARIF: %v", err)
	}
	if len(report.Runs) != 1 || len(report.Runs[0].Results) != 4 {
		t.Fatalf("unexpected SARIF shape: %#v", report)
	}
	want := map[string]string{
		"passrole-risk":                 "error",
		"external-account-trust":        "error",
		"suspicious-trust-relationship": "warning",
		"simple-privilege-escalation":   "note",
	}
	for _, result := range report.Runs[0].Results {
		expected, ok := want[result.RuleID]
		if !ok || result.Level != expected {
			t.Fatalf("unexpected SARIF result: %#v", result)
		}
	}
	if len(want) != len(report.Runs[0].Tool.Driver.Rules) {
		t.Fatalf("expected all unique rules, got %#v", report.Runs[0].Tool.Driver.Rules)
	}
}

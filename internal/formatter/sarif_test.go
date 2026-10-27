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
		{Title: "Potential PassRole Trust Relationship", Severity: "LOW", Path: []string{"a", "b"}},
		{Title: "Conditional PassRole Permission Requires Review", Severity: "HIGH", Limitations: []string{"condition not evaluated"}},
	}})
	if err != nil {
		t.Fatalf("format SARIF: %v", err)
	}

	var report SARIFReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("parse SARIF: %v", err)
	}
	if len(report.Runs) != 1 || len(report.Runs[0].Results) != 5 {
		t.Fatalf("unexpected SARIF shape: %#v", report)
	}
	want := map[string]string{
		"passrole-risk":                         "error",
		"external-account-trust":                "error",
		"suspicious-trust-relationship":         "warning",
		"potential-passrole-trust-relationship": "note",
		"conditional-passrole-review":           "error",
	}
	for _, result := range report.Runs[0].Results {
		expected, ok := want[result.RuleID]
		if !ok || result.Level != expected {
			t.Fatalf("unexpected SARIF result: %#v", result)
		}
		if result.RuleID == "conditional-passrole-review" && len(result.Properties.CloudAttackLimitations) != 1 {
			t.Fatalf("expected SARIF to preserve uncertainty, got %#v", result.Properties)
		}
	}
	if len(want) != len(report.Runs[0].Tool.Driver.Rules) {
		t.Fatalf("expected all unique rules, got %#v", report.Runs[0].Tool.Driver.Rules)
	}
}

func TestToJSONIncludesConditionalLimitations(t *testing.T) {
	output, err := ToJSON(models.Report{Findings: []models.Finding{{
		Title:       "Conditional PassRole Permission Requires Review",
		Severity:    "MEDIUM",
		Role:        "builder",
		Limitations: []string{"condition not evaluated"},
	}}})
	if err != nil {
		t.Fatalf("format JSON: %v", err)
	}
	var report JSONReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("parse JSON report: %v", err)
	}
	if len(report.Findings) != 1 || len(report.Findings[0].Limitations) != 1 || report.Findings[0].Limitations[0] != "condition not evaluated" {
		t.Fatalf("expected JSON to preserve uncertainty, got %#v", report.Findings)
	}
}

func TestTerraformChangeContextIsPreservedInJSONAndSARIF(t *testing.T) {
	statement := 2
	finding := models.Finding{
		RuleID: "passrole-risk", FindingID: "caf1_synthetic", IdentityStatus: "stable", Title: "PassRole Risk Detected", Severity: "CRITICAL", Role: "builder",
		Issue: "potential role pass", Impact: "configuration risk", ResourceAddress: "aws_iam_role_policy.builder",
		PreviousResourceAddress: "aws_iam_role_policy.old_builder", Remediation: "restrict role scope",
		RoleAddress: "aws_iam_role.builder", RelatedAddresses: []string{"aws_iam_role_policy_attachment.builder"},
		StatementIndex: &statement, ChangeClassification: models.ChangeIntroduced, ChangeSummary: "risk pattern added",
		Evidence: models.FindingEvidence{RoleReference: "builder", PolicyReference: "aws_iam_role_policy.builder", ActionPatterns: []string{"iam:PassRole"}, ResourcePatterns: []string{"*"}},
	}
	provenance := &models.ScanProvenance{SchemaVersion: "1.0", ScanID: "synthetic-scan-1", TimestampUTC: "2026-10-27T12:00:00Z", Scanner: models.ScannerProvenance{Name: "cloudattack", Edition: "community", Version: "test"}, Input: models.InputProvenance{Type: "terraform-plan", DigestAlgorithm: "sha256", ContentDigest: "abc123", DigestScope: "raw-input-bytes"}, Coverage: models.ScanCoverage{Scope: "supported-subset", Limitations: []string{"synthetic limitation"}}}
	jsonOutput, err := ToJSON(models.Report{SourceType: "terraform-plan", Provenance: provenance, Findings: []models.Finding{finding}})
	if err != nil {
		t.Fatalf("format JSON: %v", err)
	}
	var jsonReport JSONReport
	if err := json.Unmarshal([]byte(jsonOutput), &jsonReport); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}
	got := jsonReport.Findings[0]
	if jsonReport.SchemaVersion != "1.1" || jsonReport.Provenance == nil || jsonReport.Provenance.ScanID != provenance.ScanID || got.ID != "passrole-risk" || got.RuleID != "passrole-risk" || got.FindingID != finding.FindingID || got.IdentityStatus != "stable" || got.ResourceAddress != finding.ResourceAddress || got.PreviousResourceAddress != finding.PreviousResourceAddress || got.Remediation != finding.Remediation || got.Evidence == nil || got.RoleAddress != finding.RoleAddress || got.StatementIndex == nil || *got.StatementIndex != statement || got.ChangeClassification != "introduced" || len(got.RelatedAddresses) != 1 {
		t.Fatalf("JSON change context missing: %#v", got)
	}

	sarifOutput, err := ToSARIF(models.Report{Provenance: provenance, Findings: []models.Finding{finding}})
	if err != nil {
		t.Fatalf("format SARIF: %v", err)
	}
	var sarifReport SARIFReport
	if err := json.Unmarshal([]byte(sarifOutput), &sarifReport); err != nil {
		t.Fatalf("parse SARIF: %v", err)
	}
	result := sarifReport.Runs[0].Results[0]
	if result.RuleID != "passrole-risk" || result.PartialFingerprints["cloudattack/finding-v1"] != finding.FindingID || result.Properties.CloudAttackFindingID != finding.FindingID || result.Properties.CloudAttackIdentityStatus != "stable" || result.Properties.CloudAttackResourceAddress != finding.ResourceAddress || result.Properties.CloudAttackPreviousResourceAddress != finding.PreviousResourceAddress || result.Properties.CloudAttackRemediation != finding.Remediation || result.Properties.CloudAttackEvidence == nil || result.Properties.CloudAttackChangeClassification != "introduced" || result.Properties.CloudAttackStatementIndex == nil || *result.Properties.CloudAttackStatementIndex != statement || sarifReport.Runs[0].Properties == nil || sarifReport.Runs[0].Properties.CloudAttackProvenance == nil || sarifReport.Runs[0].Properties.CloudAttackProvenance.ScanID != provenance.ScanID {
		t.Fatalf("SARIF change context missing: %#v", result)
	}
}

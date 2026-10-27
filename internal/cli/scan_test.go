package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cloudattack-community/internal/formatter"
)

func TestRunScanWithInputFile(t *testing.T) {
	input := `{
  "RoleDetailList": [
    {
      "RoleName": "developer-role",
      "Arn": "arn:aws:iam::999999999999:role/developer-role",
      "RolePolicyList": [],
      "AssumeRolePolicyDocument": {
        "Statement": [
          {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": "arn:aws:iam::123456789012:root"
          }
        ]
      }
    }
  ]
}`

	dir := t.TempDir()
	inputFile := filepath.Join(dir, "iam.json")
	if err := os.WriteFile(inputFile, []byte(input), 0o600); err != nil {
		t.Fatalf("write input file: %v", err)
	}

	var exitCode int
	output := captureStdout(t, func() {
		exitCode = runScan([]string{"--input", inputFile})
	})
	if exitCode != 0 {
		t.Fatalf("expected successful scan, got exit code %d", exitCode)
	}

	if !strings.Contains(output, "Summary:\n  1 issues found") {
		t.Fatalf("expected summary for one issue, got:\n%s", output)
	}
	if !strings.Contains(output, "External Account Trust Relationship") {
		t.Fatalf("expected external trust finding, got:\n%s", output)
	}
}

func TestRunScanWithTerraformPlan(t *testing.T) {
	planFile := filepath.Join("..", "input", "testdata", "findings.json")
	var exitCode int
	output := captureStdout(t, func() {
		exitCode = runScan([]string{"--terraform-plan", planFile, "--format", "json"})
	})
	if exitCode != 0 {
		t.Fatalf("expected successful Terraform scan, got exit code %d", exitCode)
	}
	var report formatter.JSONReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("parse Terraform JSON report: %v", err)
	}
	if report.Scan.SourceType != "terraform-plan" {
		t.Fatalf("expected Terraform source type, got %q", report.Scan.SourceType)
	}
	if report.Summary.Total == 0 {
		t.Fatal("expected findings from Terraform plan")
	}
}

func TestScanInputSourcesAreMutuallyExclusiveAndRequired(t *testing.T) {
	planFile := filepath.Join("..", "input", "testdata", "safe-role.json")
	for _, args := range [][]string{
		{"--input", "iam.json", "--terraform-plan", planFile},
		{},
	} {
		if exitCode := runScan(args); exitCode != 2 {
			t.Fatalf("expected exit code 2 for args %v, got %d", args, exitCode)
		}
	}
}

func TestTerraformPlanWithoutIAMResourcesSucceeds(t *testing.T) {
	planFile := filepath.Join("..", "input", "testdata", "unrelated.json")
	var exitCode int
	output := captureStdout(t, func() {
		exitCode = runScan([]string{"--terraform-plan", planFile, "--format", "json"})
	})
	if exitCode != 0 {
		t.Fatalf("expected successful no-IAM scan, got exit code %d", exitCode)
	}
	var report formatter.JSONReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("parse no-IAM JSON report: %v", err)
	}
	if report.Scan.SourceType != "terraform-plan" || report.Summary.Total != 0 || len(report.Findings) != 0 {
		t.Fatalf("expected zero Terraform findings, got %#v", report)
	}
}

func TestTerraformPlanSupportsAllOutputFormats(t *testing.T) {
	planFile := filepath.Join("..", "input", "testdata", "findings.json")
	for _, format := range []string{"text", "json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			var exitCode int
			output := captureStdout(t, func() {
				exitCode = runScan([]string{"--terraform-plan", planFile, "--format", format})
			})
			if exitCode != 0 {
				t.Fatalf("expected successful scan, got exit code %d", exitCode)
			}
			if format == "text" {
				if !strings.Contains(output, "CloudAttack Community Edition") {
					t.Fatalf("expected text output, got:\n%s", output)
				}
				return
			}
			if format == "json" {
				var report formatter.JSONReport
				if err := json.Unmarshal([]byte(output), &report); err != nil {
					t.Fatalf("parse JSON output: %v", err)
				}
				return
			}
			var report formatter.SARIFReport
			if err := json.Unmarshal([]byte(output), &report); err != nil {
				t.Fatalf("parse SARIF output: %v", err)
			}
		})
	}
}

func TestUnsupportedTerraformPlanReturnsExitTwo(t *testing.T) {
	for _, name := range []string{"unsupported.json"} {
		t.Run(name, func(t *testing.T) {
			planFile := filepath.Join("..", "input", "testdata", name)
			if exitCode := runScan([]string{"--terraform-plan", planFile, "--format", "json"}); exitCode != 2 {
				t.Fatalf("expected exit code 2, got %d", exitCode)
			}
		})
	}
}

func TestUnknownTerraformPlanFailsClosedWithReport(t *testing.T) {
	planFile := filepath.Join("..", "input", "testdata", "unknown-critical.json")
	for _, args := range [][]string{
		{"--terraform-plan", planFile, "--format", "json"},
		{"--terraform-plan", planFile, "--format", "json", "--fail-on", "critical"},
	} {
		var exitCode int
		output := captureStdout(t, func() { exitCode = runScan(args) })
		if exitCode != 1 {
			t.Fatalf("expected incomplete Terraform state to fail closed with exit 1 for %v, got %d", args, exitCode)
		}
		var report formatter.JSONReport
		if err := json.Unmarshal([]byte(output), &report); err != nil {
			t.Fatalf("parse unknown-state report: %v", err)
		}
		if report.Summary.High != 1 || report.Findings[0].ChangeClassification != "unknown" {
			t.Fatalf("expected visible high severity unknown finding, got %#v", report)
		}
	}
}

func TestTerraformIntroducedFindingUsesSeverityGate(t *testing.T) {
	planFile := filepath.Join("..", "input", "testdata", "findings.json")
	var exitCode int
	output := captureStdout(t, func() {
		exitCode = runScan([]string{"--terraform-plan", planFile, "--format", "json", "--fail-on", "critical"})
	})
	if exitCode != 1 {
		t.Fatalf("expected introduced critical finding to fail severity gate, got %d", exitCode)
	}
	var report formatter.JSONReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("parse report: %v", err)
	}
	foundIntroduced := false
	for _, finding := range report.Findings {
		if finding.ChangeClassification == "introduced" {
			foundIntroduced = true
		}
	}
	if !foundIntroduced {
		t.Fatalf("expected introduced finding in report: %#v", report.Findings)
	}
}

func TestTerraformGateKeepsResolvedVisibleWithoutFailing(t *testing.T) {
	plan := `{"format_version":"1.2","resource_changes":[
{"address":"aws_iam_role.app","type":"aws_iam_role","change":{"actions":["no-op"],"before":{"name":"app","arn":"arn:aws:iam::123456789012:role/app","assume_role_policy":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRole\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"}}]}"},"after":{"name":"app","arn":"arn:aws:iam::123456789012:role/app","assume_role_policy":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRole\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"}}]}"}}},
{"address":"aws_iam_role_policy.permissions","type":"aws_iam_role_policy","change":{"actions":["update"],"before":{"role":"app","policy":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"iam:PassRole\",\"Resource\":\"*\"}]}"},"after":{"role":"app","policy":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::example/*\"}]}"}}}]}`
	planFile := writeScanInput(t, plan)
	var exitCode int
	output := captureStdout(t, func() {
		exitCode = runScan([]string{"--terraform-plan", planFile, "--format", "json", "--fail-on", "high"})
	})
	if exitCode != 0 {
		t.Fatalf("resolved findings should not fail severity gate, got %d", exitCode)
	}
	var report formatter.JSONReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("parse report: %v", err)
	}
	if len(report.Findings) == 0 {
		t.Fatalf("expected resolved finding retained in report: %#v", report.Findings)
	}
	for _, finding := range report.Findings {
		if finding.ChangeClassification != "resolved" {
			t.Fatalf("expected only resolved findings, got %#v", report.Findings)
		}
	}
}

func TestMalformedTerraformPlanReturnsExitTwo(t *testing.T) {
	planFile := filepath.Join("..", "input", "testdata", "malformed.json")
	if exitCode := runScan([]string{"--terraform-plan", planFile}); exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
}

func TestScanFormatDefaultsToText(t *testing.T) {
	options, err := parseScanOptions([]string{"--input", "iam.json"})
	if err != nil {
		t.Fatalf("parse options: %v", err)
	}
	if options.format != "text" {
		t.Fatalf("expected default format text, got %q", options.format)
	}
}

func TestScanExplicitTextFormat(t *testing.T) {
	inputFile := writeScanInput(t, highFindingInput())
	var exitCode int
	output := captureStdout(t, func() {
		exitCode = runScan([]string{"--input", inputFile, "--format", "text"})
	})
	if exitCode != 0 {
		t.Fatalf("expected successful scan, got exit code %d", exitCode)
	}
	if !strings.Contains(output, "=== CloudAttack Community Edition ===") {
		t.Fatalf("expected text report, got:\n%s", output)
	}
}

func TestScanJSONOutputContract(t *testing.T) {
	inputFile := writeScanInput(t, mixedFindingsInput())
	var exitCode int
	output := captureStdout(t, func() {
		exitCode = runScan([]string{"--input", inputFile, "--format", "json"})
	})
	if exitCode != 0 {
		t.Fatalf("expected successful scan, got exit code %d", exitCode)
	}

	var report formatter.JSONReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("parse JSON output: %v\n%s", err, output)
	}
	if report.SchemaVersion != "1.1" {
		t.Fatalf("expected schema version 1.1, got %q", report.SchemaVersion)
	}
	if report.Tool.Name != "cloudattack" || report.Tool.Edition != "community" || report.Tool.Version != Version {
		t.Fatalf("unexpected tool metadata: %#v", report.Tool)
	}
	if report.Scan.SourceType != "aws-iam-json" {
		t.Fatalf("unexpected source type: %q", report.Scan.SourceType)
	}
	if report.Provenance == nil || report.Provenance.ScanID == "" || report.Provenance.TimestampUTC == "" || report.Provenance.Input.ContentDigest == "" || report.Provenance.Repository != nil {
		t.Fatalf("expected generated scan provenance without invented repository metadata: %#v", report.Provenance)
	}
	if report.Summary != (formatter.JSONSummary{Total: 3, Critical: 1, High: 1, Medium: 1, Low: 0}) {
		t.Fatalf("unexpected summary: %#v", report.Summary)
	}
	if len(report.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(report.Findings))
	}

	ids := map[string]string{}
	for _, finding := range report.Findings {
		if finding.ID == "" {
			t.Fatal("expected stable finding ID")
		}
		if finding.RuleID != finding.ID || finding.FindingID == "" || finding.IdentityStatus != "stable" {
			t.Fatalf("expected separate rule and stable finding identities: %#v", finding)
		}
		if finding.Path == nil {
			t.Fatalf("expected empty path array, got null for %s", finding.ID)
		}
		ids[finding.Title] = finding.ID
	}
	if ids["PassRole Risk Detected"] != "passrole-risk" {
		t.Fatalf("unexpected PassRole ID: %q", ids["PassRole Risk Detected"])
	}
	if ids["Overly Permissive Trust Policy"] != "overly-permissive-trust" {
		t.Fatalf("unexpected trust ID: %q", ids["Overly Permissive Trust Policy"])
	}
	if ids["External AWS Principal Trust Relationship"] != "external-aws-principal-trust" {
		t.Fatalf("unexpected external-principal ID: %q", ids["External AWS Principal Trust Relationship"])
	}
	if strings.Contains(output, "CloudAttack Community Edition") || strings.Contains(output, "Advanced attack-path") {
		t.Fatalf("JSON output contains text report content:\n%s", output)
	}
}

func TestScanProvenanceIDsDigestAndOptionalRepository(t *testing.T) {
	options, err := parseScanOptions([]string{"--input", "input.json", "--scan-id", "caller-42", "--repository", "example/service", "--commit-sha", "0123456789abcdef", "--git-ref", "refs/pull/42/merge", "--pull-request", "42"})
	if err != nil {
		t.Fatalf("parse provenance options: %v", err)
	}
	raw := []byte("{ \"RoleDetailList\": [] }\n")
	provenance, err := buildScanProvenance(options, "aws-iam-json", raw)
	if err != nil {
		t.Fatalf("build provenance: %v", err)
	}
	digest := sha256.Sum256(raw)
	if provenance.ScanID != "caller-42" || provenance.Input.ContentDigest != hex.EncodeToString(digest[:]) || provenance.Input.DigestScope != "raw-input-bytes" || provenance.Repository == nil || provenance.Repository.CommitSHA != "0123456789abcdef" {
		t.Fatalf("unexpected provenance: %#v", provenance)
	}
	if _, err := parseScanOptions([]string{"--input", "input.json"}); err != nil {
		t.Fatalf("parse options without repository metadata: %v", err)
	}
	without, err := buildScanProvenance(scanOptions{}, "aws-iam-json", raw)
	if err != nil {
		t.Fatalf("build provenance without repo: %v", err)
	}
	if without.Repository != nil {
		t.Fatalf("missing repository metadata was invented: %#v", without.Repository)
	}
}

func TestScanIDsAreUniqueAndMetadataValidationIsBounded(t *testing.T) {
	first, err := newScanID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newScanID()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || len(first) != 36 || len(second) != 36 {
		t.Fatalf("expected distinct UUID scan IDs, got %q and %q", first, second)
	}
	for _, args := range [][]string{
		{"--input", "x", "--scan-id", "bad id"},
		{"--input", "x", "--scan-id", strings.Repeat("a", 129)},
		{"--input", "x", "--repository", strings.Repeat("r", 257)},
		{"--input", "x", "--commit-sha", "not-a-sha"},
		{"--input", "x", "--git-ref", "bad\nref"},
		{"--input", "x", "--pull-request", "0"},
	} {
		if _, err := parseScanOptions(args); err == nil {
			t.Errorf("expected metadata rejection for %v", args)
		}
	}
}

func TestScanProvenanceDoesNotCollectEnvironment(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "synthetic-secret-do-not-report")
	t.Setenv("GITHUB_REPOSITORY", "should-not-be-read/repository")
	provenance, err := buildScanProvenance(scanOptions{}, "aws-iam-json", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(provenance)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "synthetic-secret-do-not-report") || strings.Contains(string(encoded), "should-not-be-read") || provenance.Repository != nil {
		t.Fatalf("implicit environment provenance was collected: %s", encoded)
	}
}

func TestRunScanEmitsExplicitProvenance(t *testing.T) {
	inputFile := writeScanInput(t, `{"RoleDetailList":[]}`)
	var exitCode int
	output := captureStdout(t, func() {
		exitCode = runScan([]string{"--input", inputFile, "--format", "json", "--scan-id", "build-42", "--repository", "example/service", "--commit-sha", "0123456789abcdef", "--git-ref", "refs/heads/main", "--pull-request", "42"})
	})
	if exitCode != 0 {
		t.Fatalf("scan should pass: %d", exitCode)
	}
	var report formatter.JSONReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}
	if report.Provenance == nil || report.Provenance.ScanID != "build-42" || report.Provenance.Repository == nil || report.Provenance.Repository.Identifier != "example/service" || report.Provenance.Repository.CommitSHA != "0123456789abcdef" || report.Provenance.Repository.GitReference != "refs/heads/main" || report.Provenance.Repository.PullRequest != "42" {
		t.Fatalf("explicit provenance was not propagated: %#v", report.Provenance)
	}
}

func TestDifferentScansAndCommitsKeepLogicalFindingIdentity(t *testing.T) {
	inputFile := writeScanInput(t, highFindingInput())
	readReport := func(scanID, commit string) formatter.JSONReport {
		var exitCode int
		output := captureStdout(t, func() {
			exitCode = runScan([]string{"--input", inputFile, "--format", "json", "--scan-id", scanID, "--repository", "example/service", "--commit-sha", commit})
		})
		if exitCode != 0 {
			t.Fatalf("scan %s failed: %d", scanID, exitCode)
		}
		var report formatter.JSONReport
		if err := json.Unmarshal([]byte(output), &report); err != nil {
			t.Fatalf("parse report: %v", err)
		}
		return report
	}
	first := readReport("execution-1", "0123456789abcdef")
	second := readReport("execution-2", "fedcba9876543210")
	if first.Provenance.ScanID == second.Provenance.ScanID {
		t.Fatal("separate executions reused the scan ID")
	}
	if len(first.Findings) != len(second.Findings) || len(first.Findings) == 0 {
		t.Fatalf("unexpected findings: %d and %d", len(first.Findings), len(second.Findings))
	}
	for i := range first.Findings {
		if first.Findings[i].FindingID == "" || first.Findings[i].FindingID != second.Findings[i].FindingID {
			t.Fatalf("commit/scan metadata changed logical finding ID: %#v %#v", first.Findings[i], second.Findings[i])
		}
	}
}

func TestScanJSONFailOnHighEmitsJSONAndExitsOne(t *testing.T) {
	inputFile := writeScanInput(t, highFindingInput())
	var exitCode int
	output := captureStdout(t, func() {
		exitCode = runScan([]string{"--input", inputFile, "--format", "json", "--fail-on", "high"})
	})
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
	var report formatter.JSONReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("expected valid JSON despite threshold breach: %v", err)
	}
}

func TestScanJSONFailOnCriticalIgnoresLowerFindings(t *testing.T) {
	inputFile := writeScanInput(t, highFindingInput())
	var exitCode int
	output := captureStdout(t, func() {
		exitCode = runScan([]string{"--input", inputFile, "--format", "json", "--fail-on", "critical"})
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	var report formatter.JSONReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}
}

func TestScanJSONInvalidInputWritesNoReport(t *testing.T) {
	inputFile := writeScanInput(t, "{not-json")
	var exitCode int
	output := captureStdout(t, func() {
		exitCode = runScan([]string{"--input", inputFile, "--format", "json"})
	})
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if strings.TrimSpace(output) != "" {
		t.Fatalf("expected no JSON report on invalid input, got:\n%s", output)
	}
}

func TestScanSARIFOutputContract(t *testing.T) {
	inputFile := writeScanInput(t, mixedFindingsInput())
	var exitCode int
	output := captureStdout(t, func() {
		exitCode = runScan([]string{"--input", inputFile, "--format", "sarif"})
	})
	if exitCode != 0 {
		t.Fatalf("expected successful scan, got exit code %d", exitCode)
	}

	var report formatter.SARIFReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("parse SARIF output: %v\n%s", err, output)
	}
	if report.Version != "2.1.0" {
		t.Fatalf("expected SARIF 2.1.0, got %q", report.Version)
	}
	if report.Schema == "" {
		t.Fatal("expected SARIF schema URI")
	}
	if len(report.Runs) != 1 {
		t.Fatalf("expected one SARIF run, got %d", len(report.Runs))
	}
	run := report.Runs[0]
	if run.Tool.Driver.Name != "CloudAttack" || run.Tool.Driver.Version != Version {
		t.Fatalf("unexpected SARIF tool metadata: %#v", run.Tool.Driver)
	}
	if len(run.Results) != 3 {
		t.Fatalf("expected one result per finding, got %d", len(run.Results))
	}
	if len(run.Tool.Driver.Rules) != 3 {
		t.Fatalf("expected three unique rules, got %d", len(run.Tool.Driver.Rules))
	}

	ruleIDs := map[string]bool{}
	for _, rule := range run.Tool.Driver.Rules {
		ruleIDs[rule.ID] = true
		if rule.Name == "" || rule.ShortDescription.Text == "" || rule.DefaultConfiguration.Level == "" {
			t.Fatalf("rule missing metadata: %#v", rule)
		}
	}
	for _, id := range []string{"passrole-risk", "overly-permissive-trust", "external-aws-principal-trust"} {
		if !ruleIDs[id] {
			t.Fatalf("missing SARIF rule %q", id)
		}
	}

	levels := map[string]string{}
	severities := map[string]string{}
	for _, result := range run.Results {
		levels[result.RuleID] = result.Level
		severities[result.RuleID] = result.Properties.CloudAttackSeverity
		if result.RuleID == "" || result.Message.Text == "" {
			t.Fatalf("result missing required fields: %#v", result)
		}
	}
	if levels["passrole-risk"] != "error" || levels["overly-permissive-trust"] != "error" || levels["external-aws-principal-trust"] != "warning" {
		t.Fatalf("unexpected SARIF severity levels: %#v", levels)
	}
	if severities["passrole-risk"] != "CRITICAL" || severities["overly-permissive-trust"] != "HIGH" || severities["external-aws-principal-trust"] != "MEDIUM" {
		t.Fatalf("unexpected CloudAttack severities: %#v", severities)
	}
	if strings.Contains(output, "Community Edition") || strings.Contains(output, "Advanced attack-path") {
		t.Fatalf("SARIF output contains text report content:\n%s", output)
	}
	if strings.Contains(output, "locations") {
		t.Fatalf("SARIF output fabricated locations:\n%s", output)
	}
}

func TestScanSARIFPreservesPathWithoutLocation(t *testing.T) {
	inputFile := writeScanInput(t, externalTrustFindingInput())
	var exitCode int
	output := captureStdout(t, func() {
		exitCode = runScan([]string{"--input", inputFile, "--format", "sarif"})
	})
	if exitCode != 0 {
		t.Fatalf("expected successful scan, got exit code %d", exitCode)
	}
	var report formatter.SARIFReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("parse SARIF output: %v", err)
	}
	path := report.Runs[0].Results[0].Properties.CloudAttackPath
	if len(path) != 2 || path[0] != "developer-role" || path[1] != "123456789012:root" {
		t.Fatalf("unexpected preserved CloudAttack path: %#v", path)
	}
}

func TestScanSARIFZeroFindingsIsValid(t *testing.T) {
	inputFile := writeScanInput(t, noFindingInput())
	var exitCode int
	output := captureStdout(t, func() {
		exitCode = runScan([]string{"--input", inputFile, "--format", "sarif"})
	})
	if exitCode != 0 {
		t.Fatalf("expected successful scan, got exit code %d", exitCode)
	}
	var report formatter.SARIFReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("parse zero-finding SARIF: %v", err)
	}
	if len(report.Runs) != 1 || len(report.Runs[0].Results) != 0 || len(report.Runs[0].Tool.Driver.Rules) != 0 {
		t.Fatalf("expected one empty SARIF run: %#v", report)
	}
}

func TestScanSARIFFailOnHighEmitsValidSARIF(t *testing.T) {
	inputFile := writeScanInput(t, highFindingInput())
	var exitCode int
	output := captureStdout(t, func() {
		exitCode = runScan([]string{"--input", inputFile, "--format", "sarif", "--fail-on", "high"})
	})
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
	var report formatter.SARIFReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("expected valid SARIF despite threshold breach: %v", err)
	}
}

func TestScanSARIFInvalidInputWritesNoReport(t *testing.T) {
	inputFile := writeScanInput(t, "{not-json")
	var exitCode int
	output := captureStdout(t, func() {
		exitCode = runScan([]string{"--input", inputFile, "--format", "sarif"})
	})
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if strings.TrimSpace(output) != "" {
		t.Fatalf("expected no SARIF report on invalid input, got:\n%s", output)
	}
}

func TestScanFailOnThresholds(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		threshold string
		want      int
	}{
		{name: "critical finds critical", input: criticalFindingInput(), threshold: "critical", want: 1},
		{name: "critical ignores high", input: highFindingInput(), threshold: "critical", want: 0},
		{name: "high finds high", input: highFindingInput(), threshold: "high", want: 1},
		{name: "high finds critical", input: criticalFindingInput(), threshold: "high", want: 1},
		{name: "high ignores medium", input: mediumFindingInput(), threshold: "high", want: 0},
		{name: "medium finds medium", input: mediumFindingInput(), threshold: "medium", want: 1},
		{name: "low finds medium", input: mediumFindingInput(), threshold: "low", want: 1},
		{name: "high ignores low", input: noFindingInput(), threshold: "high", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputFile := writeScanInput(t, tt.input)
			var exitCode int
			captureStdout(t, func() {
				exitCode = runScan([]string{"--input", inputFile, "--fail-on", tt.threshold})
			})
			if exitCode != tt.want {
				t.Fatalf("expected exit code %d, got %d", tt.want, exitCode)
			}
		})
	}
}

func TestScanInvalidArgumentsAndMalformedInput(t *testing.T) {
	inputFile := writeScanInput(t, noFindingInput())
	tests := []struct {
		name string
		args []string
	}{
		{name: "invalid fail-on", args: []string{"--input", inputFile, "--fail-on", "banana"}},
		{name: "invalid format", args: []string{"--input", inputFile, "--format", "xml"}},
		{name: "malformed input", args: []string{"--input", writeScanInput(t, "{not-json")}},
		{name: "invalid IAM structure", args: []string{"--input", writeScanInput(t, `{"RoleDetailList": {}}`)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if exitCode := runScan(tt.args); exitCode != 2 {
				t.Fatalf("expected exit code 2, got %d", exitCode)
			}
		})
	}
}

func writeScanInput(t *testing.T, input string) string {
	t.Helper()
	inputFile := filepath.Join(t.TempDir(), "iam.json")
	if err := os.WriteFile(inputFile, []byte(input), 0o600); err != nil {
		t.Fatalf("write input file: %v", err)
	}
	return inputFile
}

func noFindingInput() string {
	return `{"RoleDetailList": []}`
}

func mediumFindingInput() string {
	return `{"RoleDetailList":[{"RoleName":"role","Arn":"arn:aws:iam::999999999999:role/role","AssumeRolePolicyDocument":{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"arn:aws:iam::123456789012:role/unknown"}}]}}]}`
}

func highFindingInput() string {
	return `{"RoleDetailList":[{"RoleName":"role","Arn":"arn:aws:iam::999999999999:role/role","AssumeRolePolicyDocument":{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":"*"}]}}]}`
}

func criticalFindingInput() string {
	return `{"RoleDetailList":[{"RoleName":"source","RolePolicyList":[{"PolicyDocument":{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::999999999999:role/target"}]}}]}]}`
}

func externalTrustFindingInput() string {
	return `{"RoleDetailList":[{"RoleName":"developer-role","Arn":"arn:aws:iam::999999999999:role/developer-role","AssumeRolePolicyDocument":{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":"arn:aws:iam::123456789012:root"}]}}]}`
}

func mixedFindingsInput() string {
	return `{"RoleDetailList":[
  {"RoleName":"source","RolePolicyList":[{"PolicyDocument":{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::999999999999:role/missing"}]}}]},
  {"RoleName":"open","AssumeRolePolicyDocument":{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":"*"}]}},
  {"RoleName":"suspicious","Arn":"arn:aws:iam::999999999999:role/suspicious","AssumeRolePolicyDocument":{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"arn:aws:iam::123456789012:role/unknown"}}]}}
]}`
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	originalStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	os.Stdout = writer
	output := make(chan string, 1)
	go func() {
		var buffer bytes.Buffer
		_, _ = io.Copy(&buffer, reader)
		output <- buffer.String()
	}()

	fn()

	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	os.Stdout = originalStdout

	return <-output
}

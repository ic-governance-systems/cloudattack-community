package cli

import (
	"bytes"
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
	for _, name := range []string{"unsupported.json", "unknown-critical.json"} {
		t.Run(name, func(t *testing.T) {
			planFile := filepath.Join("..", "input", "testdata", name)
			if exitCode := runScan([]string{"--terraform-plan", planFile, "--format", "json"}); exitCode != 2 {
				t.Fatalf("expected exit code 2, got %d", exitCode)
			}
		})
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
	if report.SchemaVersion != "1.0" {
		t.Fatalf("expected schema version 1.0, got %q", report.SchemaVersion)
	}
	if report.Tool.Name != "cloudattack" || report.Tool.Edition != "community" || report.Tool.Version != Version {
		t.Fatalf("unexpected tool metadata: %#v", report.Tool)
	}
	if report.Scan.SourceType != "aws-iam-json" {
		t.Fatalf("unexpected source type: %q", report.Scan.SourceType)
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
	if ids["Suspicious Trust Relationship"] != "suspicious-trust-relationship" {
		t.Fatalf("unexpected suspicious-trust ID: %q", ids["Suspicious Trust Relationship"])
	}
	if strings.Contains(output, "CloudAttack Community Edition") || strings.Contains(output, "Advanced attack-path") {
		t.Fatalf("JSON output contains text report content:\n%s", output)
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
	for _, id := range []string{"passrole-risk", "overly-permissive-trust", "suspicious-trust-relationship"} {
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
	if levels["passrole-risk"] != "error" || levels["overly-permissive-trust"] != "error" || levels["suspicious-trust-relationship"] != "warning" {
		t.Fatalf("unexpected SARIF severity levels: %#v", levels)
	}
	if severities["passrole-risk"] != "CRITICAL" || severities["overly-permissive-trust"] != "HIGH" || severities["suspicious-trust-relationship"] != "MEDIUM" {
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
	return `{"RoleDetailList":[{"RoleName":"role","AssumeRolePolicyDocument":{"Statement":[{"Principal":"arn:aws:iam::123456789012:role/unknown"}]}}]}`
}

func highFindingInput() string {
	return `{"RoleDetailList":[{"RoleName":"role","Arn":"arn:aws:iam::999999999999:role/role","AssumeRolePolicyDocument":{"Statement":[{"Principal":"*"}]}}]}`
}

func criticalFindingInput() string {
	return `{"RoleDetailList":[{"RoleName":"source","RolePolicyList":[{"PolicyDocument":{"Statement":[{"Action":"iam:PassRole","Resource":"arn:aws:iam::999999999999:role/target"}]}}]}]}`
}

func externalTrustFindingInput() string {
	return `{"RoleDetailList":[{"RoleName":"developer-role","Arn":"arn:aws:iam::999999999999:role/developer-role","AssumeRolePolicyDocument":{"Statement":[{"Principal":"arn:aws:iam::123456789012:root"}]}}]}`
}

func mixedFindingsInput() string {
	return `{"RoleDetailList":[
  {"RoleName":"source","RolePolicyList":[{"PolicyDocument":{"Statement":[{"Action":"iam:PassRole","Resource":"arn:aws:iam::999999999999:role/missing"}]}}]},
  {"RoleName":"open","AssumeRolePolicyDocument":{"Statement":[{"Principal":"*"}]}},
  {"RoleName":"suspicious","AssumeRolePolicyDocument":{"Statement":[{"Principal":"arn:aws:iam::123456789012:role/unknown"}]}}
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

	fn()

	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	os.Stdout = originalStdout

	var buffer bytes.Buffer
	if _, err := io.Copy(&buffer, reader); err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	return buffer.String()
}

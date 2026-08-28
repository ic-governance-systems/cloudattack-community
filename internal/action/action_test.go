package action

import (
	"os"
	"strings"
	"testing"
)

func TestActionMetadataDeclaresContract(t *testing.T) {
	data, err := os.ReadFile("../../action.yml")
	if err != nil {
		t.Fatalf("read action metadata: %v", err)
	}
	metadata := string(data)
	for _, required := range []string{
		"name: CloudAttack Community",
		"using: composite",
		"terraform-plan:",
		"required: true",
		"fail-on:",
		"default: high",
		"format:",
		"default: sarif",
		"exit-code:",
		"go build -trimpath",
		"cd \"$GITHUB_ACTION_PATH\"",
		"--terraform-plan \"$PLAN_PATH\"",
		"--format \"$FORMAT\"",
		"--fail-on \"$FAIL_ON\"",
		"exit \"$status\"",
	} {
		if !strings.Contains(metadata, required) {
			t.Errorf("action metadata missing %q", required)
		}
	}
}

func TestActionPreservesReportAndExitFiles(t *testing.T) {
	data, err := os.ReadFile("../../action.yml")
	if err != nil {
		t.Fatalf("read action metadata: %v", err)
	}
	metadata := string(data)
	if !strings.Contains(metadata, "cloudattack.sarif") || !strings.Contains(metadata, "report_file=$report_file") {
		t.Fatal("action does not declare deterministic report preservation")
	}
	if !strings.Contains(metadata, "set +e") || !strings.Contains(metadata, "status=$?") || !strings.Contains(metadata, "exit_code=$status") {
		t.Fatal("action does not preserve the CLI exit status")
	}
}

func TestDogfoodWorkflowUsesLocalActionAndAlwaysUploadsSARIF(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/cloudattack-fixture.yml")
	if err != nil {
		t.Fatalf("read dogfood workflow: %v", err)
	}
	workflow := string(data)
	for _, required := range []string{
		"uses: ./",
		"terraform-plan: internal/input/testdata/safe-role.json",
		"terraform-plan: internal/input/testdata/findings.json",
		"terraform-plan: internal/input/testdata/malformed.json",
		"fail-on: high",
		"format: sarif",
		"continue-on-error: true",
		"actions/upload-artifact@v4",
		"if: ${{ always() }}",
		"github/codeql-action/upload-sarif@v3",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("workflow missing %q", required)
		}
	}
}

package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

	output := captureStdout(t, func() {
		runScan([]string{"--input", inputFile})
	})

	if !strings.Contains(output, "Summary:\n  1 issues found") {
		t.Fatalf("expected summary for one issue, got:\n%s", output)
	}
	if !strings.Contains(output, "External Account Trust Relationship") {
		t.Fatalf("expected external trust finding, got:\n%s", output)
	}
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

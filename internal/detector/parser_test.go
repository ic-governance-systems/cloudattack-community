package detector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseIAMRejectsMalformedJSON(t *testing.T) {
	if _, err := ParseIAM([]byte(`{"RoleDetailList":`)); err == nil {
		t.Fatal("expected malformed JSON error")
	}
}

func TestParseIAMAcceptsSupportedInputAndUnknownFields(t *testing.T) {
	data := []byte(`{
  "Metadata": {"source": "test"},
  "RoleDetailList": [{
    "RoleName": "developer-role",
    "Arn": "arn:aws:iam::123456789012:role/developer-role",
    "RolePolicyList": [{
      "PolicyDocument": {"Statement": [{"Action": "iam:PassRole", "Resource": "*"}]},
      "UnrelatedPolicyMetadata": true
    }],
    "AssumeRolePolicyDocument": {"Statement": [{"Principal": "*"}]},
    "UnrelatedRoleMetadata": "allowed"
  }]
}`)

	roles, err := ParseIAM(data)
	if err != nil {
		t.Fatalf("parse supported IAM input: %v", err)
	}
	if len(roles) != 1 || roles[0].Name != "developer-role" {
		t.Fatalf("unexpected parsed roles: %#v", roles)
	}
}

func TestParseIAMRejectsInvalidStructures(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "roles wrong type", data: `{"RoleDetailList": {}}`},
		{name: "role wrong type", data: `{"RoleDetailList": ["role"]}`},
		{name: "policy list wrong type", data: `{"RoleDetailList":[{"RoleName":"role","RolePolicyList":{}}]}`},
		{name: "statement wrong type", data: `{"RoleDetailList":[{"RoleName":"role","AssumeRolePolicyDocument":{"Statement":"bad"}}]}`},
		{name: "principal wrong type", data: `{"RoleDetailList":[{"RoleName":"role","AssumeRolePolicyDocument":{"Statement":[{"Principal":false}]}}]}`},
		{name: "action item wrong type", data: `{"RoleDetailList":[{"RoleName":"role","RolePolicyList":[{"PolicyDocument":{"Statement":[{"Action":["iam:PassRole",false]}]}}]}]}`},
		{name: "malformed encoded policy document", data: `{"RoleDetailList":[{"RoleName":"role","RolePolicyList":[{"PolicyDocument":"{bad"}]}]}`},
		{name: "unsupported object", data: `{"notIAM": true}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseIAM([]byte(tt.data)); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestParseIAMAcceptsEmptyRoles(t *testing.T) {
	for _, data := range []string{`{"RoleDetailList": []}`, `{"Roles": []}`, `[]`} {
		roles, err := ParseIAM([]byte(data))
		if err != nil {
			t.Fatalf("parse empty IAM input %s: %v", data, err)
		}
		if len(roles) != 0 {
			t.Fatalf("expected no roles, got %d", len(roles))
		}
	}
}

func TestParseIAMAcceptsExistingSampleFiles(t *testing.T) {
	paths := []string{
		filepath.Join("..", "..", "examples", "iam.json"),
		filepath.Join("..", "..", "sample-data", "sample.json"),
		filepath.Join("..", "..", "sample-data", "chain-sample.json"),
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture %s: %v", path, err)
		}
		if _, err := ParseIAM(data); err != nil {
			t.Fatalf("parse fixture %s: %v", path, err)
		}
	}
}

package detector

import (
	"strings"
	"testing"

	"cloudattack-community/internal/models"
)

func TestDetectPassRoleAllowsExactAndWildcardActions(t *testing.T) {
	for _, action := range []string{"iam:PassRole", "IAM:PASSROLE", "iam:*", "*", "iam:Pass*", "iam:Pass?ole"} {
		t.Run(action, func(t *testing.T) {
			findings := DetectPassRole([]models.Role{{Name: "developer", Policies: []models.Policy{{
				Effect: "Allow", Actions: []string{action}, Resources: []string{"arn:aws:iam::123456789012:role/admin"},
			}}}})
			if len(findings) != 1 || findings[0].Title != "PassRole Risk Detected" {
				t.Fatalf("expected PassRole finding for %q, got %#v", action, findings)
			}
			if !strings.Contains(findings[0].Impact, "does not prove") {
				t.Fatalf("finding should describe potential risk, got %q", findings[0].Impact)
			}
		})
	}
}

func TestDetectPassRoleRejectsDenyAndUnrelatedSubstrings(t *testing.T) {
	for _, policy := range []models.Policy{
		{Effect: "Deny", Actions: []string{"iam:PassRole"}, Resources: []string{"*"}},
		{Effect: "Allow", Actions: []string{"notiam:PassRole"}, Resources: []string{"*"}},
		{Effect: "Allow", Actions: []string{"iam:ListRoles"}, Resources: []string{"*"}},
		{Effect: "Allow", Actions: []string{"iam:PassRole"}, Resources: []string{"arn:aws:s3:::bucket/*"}},
	} {
		if findings := DetectPassRole([]models.Role{{Name: "role", Policies: []models.Policy{policy}}}); len(findings) != 0 {
			t.Fatalf("expected no PassRole finding for %#v, got %#v", policy, findings)
		}
	}
}

func TestDetectPassRoleMarksUnevaluatedConditions(t *testing.T) {
	findings := DetectPassRole([]models.Role{{Name: "developer", Policies: []models.Policy{{
		Effect: "Allow", Actions: []string{"iam:PassRole"}, Resources: []string{"*"},
		Condition: map[string]map[string]interface{}{"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}},
	}}}})
	if len(findings) != 1 || findings[0].Severity != "HIGH" || len(findings[0].Limitations) == 0 {
		t.Fatalf("expected explicit conditional uncertainty, got %#v", findings)
	}
	if !strings.Contains(findings[0].Issue, "unevaluated conditions") {
		t.Fatalf("expected the issue to disclose unevaluated conditions, got %q", findings[0].Issue)
	}
}

func TestDetectTrustInterpretsSupportedPrincipalTypes(t *testing.T) {
	tests := []struct {
		name      string
		accountID string
		statement models.Policy
		wantTitle string
	}{
		{name: "external root", accountID: "999999999999", statement: trustStatement("AWS", "arn:aws:iam::123456789012:root"), wantTitle: "External Account Trust Relationship"},
		{name: "same account root", accountID: "123456789012", statement: trustStatement("AWS", "arn:aws:iam::123456789012:root")},
		{name: "external role", accountID: "999999999999", statement: trustStatement("AWS", "arn:aws:iam::123456789012:role/ci-role"), wantTitle: "External AWS Principal Trust Relationship"},
		{name: "same account role", accountID: "123456789012", statement: trustStatement("AWS", "arn:aws:iam::123456789012:role/ci-role")},
		{name: "service", statement: trustStatement("Service", "lambda.amazonaws.com")},
		{name: "federated", statement: trustStatement("Federated", "arn:aws:iam::123456789012:oidc-provider/example")},
		{name: "deny external root", accountID: "999999999999", statement: models.Policy{Effect: "Deny", Principals: []models.Principal{{Type: "AWS", Values: []string{"arn:aws:iam::123456789012:root"}}}}},
		{name: "open principal", statement: trustStatement("*", "*"), wantTitle: "Overly Permissive Trust Policy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := DetectAssumeRole([]models.Role{{Name: "target", AccountID: tt.accountID, Trust: []models.Policy{tt.statement}}})
			if tt.wantTitle == "" {
				if len(findings) != 0 {
					t.Fatalf("expected no trust finding, got %#v", findings)
				}
				return
			}
			if len(findings) != 1 || findings[0].Title != tt.wantTitle {
				t.Fatalf("expected %q finding, got %#v", tt.wantTitle, findings)
			}
		})
	}
}

func TestTrustConditionIsPreservedAndReportedAsLimitation(t *testing.T) {
	statement := trustStatement("AWS", "arn:aws:iam::123456789012:root")
	statement.Condition = map[string]map[string]interface{}{"StringEquals": {"sts:ExternalId": "customer-123"}}
	findings := DetectAssumeRole([]models.Role{{Name: "target", AccountID: "999999999999", Trust: []models.Policy{statement}}})
	if len(findings) != 1 || len(findings[0].Limitations) != 1 {
		t.Fatalf("expected trust finding with condition caveat, got %#v", findings)
	}
}

func TestDetectChainsReportsOnlyPotentialUnconditionalAllowPattern(t *testing.T) {
	roles := []models.Role{
		{Name: "source", Policies: []models.Policy{{Effect: "Allow", Actions: []string{"iam:*"}, Resources: []string{"arn:aws:iam::123456789012:role/target"}}}},
		{Name: "target", AccountID: "123456789012", Trust: []models.Policy{trustStatement("Service", "lambda.amazonaws.com")}},
	}
	findings := DetectChains(roles)
	if len(findings) != 1 || findings[0].Title != "Potential PassRole Trust Relationship" {
		t.Fatalf("expected potential one-hop risk pattern, got %#v", findings)
	}
	if strings.Contains(strings.ToLower(findings[0].Title), "escalation") || !strings.Contains(findings[0].Impact, "does not prove") {
		t.Fatalf("finding overstates exploitability: %#v", findings[0])
	}

	roles[0].Policies[0].Effect = "Deny"
	if findings := DetectChains(roles); len(findings) != 0 {
		t.Fatalf("deny statement must not form a chain, got %#v", findings)
	}
	roles[0].Policies[0].Effect = "Allow"
	roles[0].Policies[0].Condition = map[string]map[string]interface{}{"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}
	if findings := DetectChains(roles); len(findings) != 0 {
		t.Fatalf("unevaluated conditional permissions must not form a chain, got %#v", findings)
	}
	roles[0].Policies[0].Condition = nil
	roles[1].Trust[0].Condition = map[string]map[string]interface{}{"StringEquals": {"sts:ExternalId": "tenant"}}
	if findings := DetectChains(roles); len(findings) != 1 || len(findings[0].Limitations) != 1 {
		t.Fatalf("target trust condition must be disclosed as uncertainty, got %#v", findings)
	}
	roles[1].AccountID = "999999999999"
	if findings := DetectChains(roles); len(findings) != 0 {
		t.Fatalf("PassRole resource for a different account must not match target role, got %#v", findings)
	}
}

func trustStatement(principalType, value string) models.Policy {
	return models.Policy{Effect: "Allow", Actions: []string{"sts:AssumeRole"}, Principals: []models.Principal{{Type: principalType, Values: []string{value}}}}
}

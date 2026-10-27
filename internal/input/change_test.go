package input

import (
	"encoding/json"
	"testing"

	"cloudattack-community/internal/detector"
	"cloudattack-community/internal/models"
)

const (
	roleSafe        = `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"Service":"lambda.amazonaws.com"}}]}`
	roleRisk        = `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":"*"}]}`
	passRole        = `{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::123456789012:role/restricted"}]}`
	passAll         = `{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}]}`
	safePolicy      = `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::example/*"}]}`
	conditionalPass = `{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*","Condition":{"StringEquals":{"iam:PassedToService":"lambda.amazonaws.com"}}}]}`
)

func TestTerraformRiskChangeClassifications(t *testing.T) {
	tests := []struct {
		name      string
		changes   []map[string]interface{}
		wantRule  string
		wantClass models.ChangeClassification
		wantCount int
	}{
		{name: "new risky PassRole", changes: []map[string]interface{}{roleChange("no-op", roleState("app", roleSafe), roleState("app", roleSafe)), inlineChange("create", nil, inlineState("app", passRole))}, wantRule: "passrole-risk", wantClass: models.ChangeIntroduced, wantCount: 1},
		{name: "existing unchanged PassRole", changes: []map[string]interface{}{roleChange("no-op", roleState("app", roleSafe), roleState("app", roleSafe)), inlineChange("no-op", inlineState("app", passRole), inlineState("app", passRole))}, wantRule: "passrole-risk", wantClass: models.ChangeUnchanged, wantCount: 1},
		{name: "Terraform address move preserves identity", changes: []map[string]interface{}{roleChange("no-op", roleState("app", roleSafe), roleState("app", roleSafe)), movedInlineChange()}, wantRule: "passrole-risk", wantClass: models.ChangeUnchanged, wantCount: 1},
		{name: "permission broadens to all roles", changes: []map[string]interface{}{roleChange("no-op", roleState("app", roleSafe), roleState("app", roleSafe)), inlineChange("update", inlineState("app", passRole), inlineState("app", passAll))}, wantRule: "passrole-risk", wantClass: models.ChangeChanged, wantCount: 1},
		{name: "permission narrows from all roles", changes: []map[string]interface{}{roleChange("no-op", roleState("app", roleSafe), roleState("app", roleSafe)), inlineChange("update", inlineState("app", passAll), inlineState("app", passRole))}, wantRule: "passrole-risk", wantClass: models.ChangeChanged, wantCount: 1},
		{name: "risky permission removed", changes: []map[string]interface{}{roleChange("no-op", roleState("app", roleSafe), roleState("app", roleSafe)), inlineChange("update", inlineState("app", passRole), inlineState("app", safePolicy))}, wantRule: "passrole-risk", wantClass: models.ChangeResolved, wantCount: 1},
		{name: "role trust added", changes: []map[string]interface{}{roleChange("update", roleState("app", roleSafe), roleState("app", roleRisk))}, wantRule: "overly-permissive-trust", wantClass: models.ChangeIntroduced, wantCount: 1},
		{name: "role trust removed", changes: []map[string]interface{}{roleChange("update", roleState("app", roleRisk), roleState("app", roleSafe))}, wantRule: "overly-permissive-trust", wantClass: models.ChangeResolved, wantCount: 1},
		{name: "attachment adds PassRole", changes: managedAttachmentChanges("create"), wantRule: "passrole-risk", wantClass: models.ChangeIntroduced, wantCount: 1},
		{name: "attachment removes PassRole", changes: managedAttachmentChanges("delete"), wantRule: "passrole-risk", wantClass: models.ChangeResolved, wantCount: 1},
		{name: "role deletion resolves trust risk", changes: []map[string]interface{}{roleChange("delete", roleState("app", roleRisk), nil)}, wantRule: "overly-permissive-trust", wantClass: models.ChangeResolved, wantCount: 1},
		{name: "role replacement preserves trust risk", changes: []map[string]interface{}{roleChange("replace", roleState("app", roleRisk), roleState("app", roleRisk))}, wantRule: "overly-permissive-trust", wantClass: models.ChangeUnchanged, wantCount: 1},
		{name: "unknown before policy state", changes: []map[string]interface{}{roleChange("no-op", roleState("app", roleSafe), roleState("app", roleSafe)), unknownBeforeInline()}, wantRule: "passrole-risk", wantClass: models.ChangeUnknown, wantCount: 1},
		{name: "incomplete before policy context", changes: []map[string]interface{}{roleChange("no-op", roleState("app", roleSafe), roleState("app", roleSafe)), inlineChange("update", nil, inlineState("app", passRole))}, wantRule: "passrole-risk", wantClass: models.ChangeUnknown, wantCount: 1},
		{name: "conditional runtime context", changes: []map[string]interface{}{roleChange("no-op", roleState("app", roleSafe), roleState("app", roleSafe)), inlineChange("create", nil, inlineState("app", conditionalPass))}, wantRule: "conditional-passrole-review", wantClass: models.ChangeUnknown, wantCount: 1},
		{name: "safe plan", changes: []map[string]interface{}{roleChange("no-op", roleState("app", roleSafe), roleState("app", roleSafe)), inlineChange("create", nil, inlineState("app", safePolicy))}, wantCount: 0},
		{name: "same rule in separate resources", changes: []map[string]interface{}{roleChange("no-op", roleState("app", roleSafe), roleState("app", roleSafe)), inlineChangeAt("create", "aws_iam_role_policy.first", nil, inlineState("app", passRole)), inlineChangeAt("create", "aws_iam_role_policy.second", nil, inlineState("app", passAll))}, wantRule: "passrole-risk", wantClass: models.ChangeIntroduced, wantCount: 2},
		{name: "ambiguous multiple target rewrite", changes: []map[string]interface{}{roleChange("no-op", roleState("app", roleSafe), roleState("app", roleSafe)), inlineChange("update", inlineState("app", multiTargetPolicy("old-a", "old-b")), inlineState("app", multiTargetPolicy("new-a", "new-b")))}, wantRule: "passrole-risk", wantClass: models.ChangeUnknown, wantCount: 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := planJSON(t, tt.changes...)
			plan, err := ParseTerraformPlan(data)
			if err != nil {
				t.Fatalf("parse plan: %v", err)
			}
			findings := detector.RunTerraformAnalysis(plan)
			detector.AssignFindingIdentities(findings, plan)
			var matches []models.Finding
			for _, finding := range findings {
				if finding.RuleID == tt.wantRule {
					matches = append(matches, finding)
				}
			}
			if len(matches) != tt.wantCount {
				t.Fatalf("expected %d %q findings, got %d: %#v", tt.wantCount, tt.wantRule, len(matches), findings)
			}
			for _, finding := range matches {
				if finding.ChangeClassification != tt.wantClass {
					t.Errorf("expected %s classification, got %s (%s)", tt.wantClass, finding.ChangeClassification, finding.ChangeSummary)
				}
				if finding.ResourceAddress == "" {
					t.Errorf("finding has no Terraform resource address: %#v", finding)
				}
				if finding.FindingID == "" || finding.IdentityStatus != "stable" {
					t.Errorf("expected stable occurrence identity: %#v", finding)
				}
			}
		})
	}
}

func TestResolvedAndReintroducedFindingKeepsIdentity(t *testing.T) {
	role := roleChange("no-op", roleState("app", roleSafe), roleState("app", roleSafe))
	resolvedPlan, err := ParseTerraformPlan(planJSON(t, role, inlineChange("update", inlineState("app", passRole), inlineState("app", safePolicy))))
	if err != nil {
		t.Fatal(err)
	}
	resolved := detector.RunTerraformAnalysis(resolvedPlan)
	detector.AssignFindingIdentities(resolved, resolvedPlan)
	var oldID string
	for _, finding := range resolved {
		if finding.RuleID == "passrole-risk" {
			oldID = finding.FindingID
			if finding.ChangeClassification != models.ChangeResolved {
				t.Fatalf("expected resolved finding, got %#v", finding)
			}
		}
	}
	if oldID == "" {
		t.Fatal("resolved finding has no identity")
	}

	introducedPlan, err := ParseTerraformPlan(planJSON(t, roleChange("no-op", roleState("app", roleSafe), roleState("app", roleSafe)), inlineChange("create", nil, inlineState("app", passRole))))
	if err != nil {
		t.Fatal(err)
	}
	introduced := detector.RunTerraformAnalysis(introducedPlan)
	detector.AssignFindingIdentities(introduced, introducedPlan)
	for _, finding := range introduced {
		if finding.RuleID == "passrole-risk" {
			if finding.ChangeClassification != models.ChangeIntroduced {
				t.Fatalf("expected introduced finding, got %#v", finding)
			}
			if finding.FindingID != oldID {
				t.Fatalf("reintroduced logical occurrence changed identity: old %q new %q", oldID, finding.FindingID)
			}
			return
		}
	}
	t.Fatal("introduced risk not found")
}

func TestTerraformMalformedActionsFailClosed(t *testing.T) {
	_, err := ParseTerraformPlan(planJSON(t, map[string]interface{}{"address": "aws_iam_role.bad", "type": "aws_iam_role", "change": map[string]interface{}{"actions": []string{"forget"}}}))
	if err == nil {
		t.Fatal("expected malformed action to fail")
	}
}

func TestTerraformUnknownFindingUsesHighSeverity(t *testing.T) {
	plan := models.TerraformPlan{Uncertainties: []models.TerraformUncertainty{{Address: "aws_iam_role.x", Side: "after", Reason: "unknown test value"}}}
	findings := detector.RunTerraformAnalysis(plan)
	if len(findings) != 1 || findings[0].ChangeClassification != models.ChangeUnknown || findings[0].Severity != "HIGH" {
		t.Fatalf("expected high severity unknown finding, got %#v", findings)
	}
}

func planJSON(t *testing.T, changes ...map[string]interface{}) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]interface{}{"format_version": "1.2", "resource_changes": changes})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func roleState(name, trust string) map[string]interface{} {
	return map[string]interface{}{"name": name, "arn": "arn:aws:iam::123456789012:role/" + name, "assume_role_policy": trust}
}
func inlineState(role, policy string) map[string]interface{} {
	return map[string]interface{}{"role": role, "policy": policy}
}
func multiTargetPolicy(first, second string) string {
	return `{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":["arn:aws:iam::123456789012:role/` + first + `","arn:aws:iam::123456789012:role/` + second + `"]}]}`
}

func roleChange(action string, before, after map[string]interface{}) map[string]interface{} {
	return stateChange("aws_iam_role.app", "aws_iam_role", action, before, after, nil)
}
func inlineChange(action string, before, after map[string]interface{}) map[string]interface{} {
	return inlineChangeAt(action, "aws_iam_role_policy.permissions", before, after)
}
func inlineChangeAt(action, address string, before, after map[string]interface{}) map[string]interface{} {
	return stateChange(address, "aws_iam_role_policy", action, before, after, nil)
}
func movedInlineChange() map[string]interface{} {
	change := inlineChangeAt("no-op", "aws_iam_role_policy.renamed", inlineState("app", passRole), inlineState("app", passRole))
	change["previous_address"] = "aws_iam_role_policy.permissions"
	return change
}
func unknownBeforeInline() map[string]interface{} {
	return stateChange("aws_iam_role_policy.permissions", "aws_iam_role_policy", "update", inlineState("app", safePolicy), inlineState("app", passRole), map[string]interface{}{"before_unknown": map[string]interface{}{"policy": true}})
}

func managedAttachmentChanges(action string) []map[string]interface{} {
	policyState := map[string]interface{}{"name": "passrole", "arn": "arn:aws:iam::123456789012:policy/passrole", "id": "arn:aws:iam::123456789012:policy/passrole", "policy": passRole}
	changes := []map[string]interface{}{roleChange("no-op", roleState("app", roleSafe), roleState("app", roleSafe)), stateChange("aws_iam_policy.passrole", "aws_iam_policy", "no-op", policyState, policyState, nil)}
	var before, after map[string]interface{}
	if action == "create" {
		after = map[string]interface{}{"role": "app", "policy_arn": policyState["arn"]}
	} else {
		before = map[string]interface{}{"role": "app", "policy_arn": policyState["arn"]}
	}
	changes = append(changes, stateChange("aws_iam_role_policy_attachment.passrole", "aws_iam_role_policy_attachment", action, before, after, nil))
	return changes
}

func stateChange(address, resourceType, action string, before, after map[string]interface{}, extra map[string]interface{}) map[string]interface{} {
	actions := []string{action}
	if action == "replace" {
		actions = []string{"delete", "create"}
	}
	change := map[string]interface{}{"actions": actions, "before": before, "after": after, "before_unknown": map[string]interface{}{}, "after_unknown": map[string]interface{}{}}
	for key, value := range extra {
		change[key] = value
	}
	return map[string]interface{}{"address": address, "type": resourceType, "change": change}
}

package detector

import (
	"testing"

	"cloudattack-community/internal/models"
)

func TestFindingIdentityStableAndResourceScoped(t *testing.T) {
	findings := []models.Finding{
		{RuleID: "passrole-risk", IdentityRole: "123456789012|builder", ResourceAddress: "aws_iam_role_policy.a", IdentitySubject: "arn:aws:iam::123456789012:role/target"},
		{RuleID: "passrole-risk", IdentityRole: "123456789012|builder", ResourceAddress: "aws_iam_role_policy.b", IdentitySubject: "arn:aws:iam::123456789012:role/target"},
	}
	AssignFindingIdentities(findings, models.TerraformPlan{})
	if findings[0].FindingID == "" || findings[1].FindingID == "" || findings[0].FindingID == findings[1].FindingID {
		t.Fatalf("same rule on separate resources needs distinct stable IDs: %#v", findings)
	}
	firstID := findings[0].FindingID
	repeated := []models.Finding{findings[0]}
	repeated[0].FindingID, repeated[0].IdentityStatus = "", ""
	AssignFindingIdentities(repeated, models.TerraformPlan{})
	if repeated[0].FindingID != firstID {
		t.Fatalf("equivalent scan changed finding ID: got %q want %q", repeated[0].FindingID, firstID)
	}
	// Commit and scan metadata are intentionally not identity inputs.
	repeated[0].ChangeClassification = models.ChangeChanged
	AssignFindingIdentities(repeated, models.TerraformPlan{})
	if repeated[0].FindingID != firstID {
		t.Fatalf("classification changed finding ID: got %q want %q", repeated[0].FindingID, firstID)
	}
}

func TestFindingIdentitySurvivesStatementReorderingAndUniqueMove(t *testing.T) {
	baseStatement := 0
	base := models.Finding{RuleID: "external-account-trust", RoleAddress: "aws_iam_role.app", ResourceAddress: "aws_iam_role.app", StatementIndex: &baseStatement, IdentityRole: "123456789012|app", IdentitySubject: "AWS:arn:aws:iam::999999999999:root"}
	moved := base
	moved.RoleAddress, moved.ResourceAddress = "aws_iam_role.renamed", "aws_iam_role.renamed"
	statement := 7 // Evidence ordering changes; the identity algorithm ignores this index.
	moved.StatementIndex = &statement
	plan := models.TerraformPlan{Changes: []models.TerraformResourceChange{{Address: "aws_iam_role.renamed", PreviousAddress: "aws_iam_role.app"}}}
	baseFindings, movedFindings := []models.Finding{base}, []models.Finding{moved}
	AssignFindingIdentities(baseFindings, models.TerraformPlan{})
	AssignFindingIdentities(movedFindings, plan)
	if baseFindings[0].FindingID == "" || baseFindings[0].FindingID != movedFindings[0].FindingID {
		t.Fatalf("unique Terraform move and statement reordering should preserve the logical ID: %#v %#v", baseFindings, movedFindings)
	}
}

func TestFindingIdentityMarksAmbiguousOccurrences(t *testing.T) {
	findings := []models.Finding{
		{RuleID: "passrole-risk", IdentityRole: "123456789012|builder", ResourceAddress: "aws_iam_role_policy.permissions", IdentitySubject: "*"},
		{RuleID: "passrole-risk", IdentityRole: "123456789012|builder", ResourceAddress: "aws_iam_role_policy.permissions", IdentitySubject: "*"},
	}
	AssignFindingIdentities(findings, models.TerraformPlan{})
	for _, finding := range findings {
		if finding.FindingID != "" || finding.IdentityStatus != "ambiguous" {
			t.Fatalf("ambiguous duplicate occurrence received a definitive ID: %#v", finding)
		}
	}

	moved := []models.Finding{{RuleID: "passrole-risk", RoleAddress: "aws_iam_role.new", ResourceAddress: "aws_iam_role_policy.new", IdentityRole: "builder", IdentitySubject: "*"}}
	ambiguousPlan := models.TerraformPlan{Changes: []models.TerraformResourceChange{
		{Address: "aws_iam_role.new", PreviousAddress: "aws_iam_role.old"},
		{Address: "aws_iam_role_policy.new", PreviousAddress: "aws_iam_role_policy.old"},
		{Address: "aws_iam_policy.new", PreviousAddress: "aws_iam_role_policy.old"},
	}}
	AssignFindingIdentities(moved, ambiguousPlan)
	if moved[0].FindingID != "" || moved[0].IdentityStatus != "ambiguous" {
		t.Fatalf("ambiguous previous address was treated as stable: %#v", moved[0])
	}
}

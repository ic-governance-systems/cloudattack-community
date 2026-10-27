package detector

import (
	"encoding/json"
	"fmt"
	"strings"

	"cloudattack-community/internal/models"
)

const conditionReviewNote = "IAM conditions are preserved but not evaluated; effective access depends on runtime context."

// DetectPassRole reports allow statements whose action pattern can match
// iam:PassRole. It intentionally does not claim that the permission is usable
// in a particular runtime context.
func DetectPassRole(roles []models.Role) []models.Finding {
	findings := []models.Finding{}
	for _, role := range roles {
		for _, policy := range role.Policies {
			if policy.Effect != "Allow" || !actionsCanMatchPassRole(policy.Actions) {
				continue
			}
			for resourceIndex, resource := range policy.Resources {
				if !isPotentialRoleResource(resource) {
					continue
				}
				target := passRoleTarget(resource)
				finding := models.Finding{
					RuleID:          "passrole-risk",
					Severity:        "CRITICAL",
					Title:           "PassRole Risk Detected",
					Role:            role.Name,
					Issue:           fmt.Sprintf("Role may pass iam:PassRole permission to %s", target),
					Impact:          "This permission pattern may let the role pass the target role to an AWS service; CloudAttack does not prove that it is exploitable.",
					ResourceAddress: policy.Address, RoleAddress: role.Address,
					RelatedAddresses: append([]string{}, policy.AttachmentAddresses...),
					StatementIndex:   intPointer(policy.StatementIndex),
					IdentityRole:     role.AccountID + "|" + role.Name,
					IdentitySubject:  resource,
					IdentityPolicy:   policy.Address,
					Evidence: models.FindingEvidence{
						RoleReference: role.Name, PolicyReference: policy.Address,
						ActionPatterns: append([]string{}, policy.Actions...), ResourcePatterns: []string{resource},
						ConditionPresent: len(policy.Condition) > 0,
					},
				}
				finding.MatchKey = findingMatchKey(finding.RuleID, role.Address, policy.Address, policy.StatementIndex, resourceIndex, target)
				finding.ContextFingerprint = fingerprint(struct {
					RoleName, AccountID string
					Effect              string
					Actions, Resources  []string
					Condition           map[string]map[string]interface{}
				}{role.Name, role.AccountID, policy.Effect, policy.Actions, policy.Resources, policy.Condition})
				if len(policy.Condition) > 0 {
					finding.RuleID = "conditional-passrole-review"
					finding.MatchKey = findingMatchKey(finding.RuleID, role.Address, policy.Address, policy.StatementIndex, resourceIndex, target)
					finding.Severity = "HIGH"
					finding.Title = "Conditional PassRole Permission Requires Review"
					finding.Issue = fmt.Sprintf("Allow statement may match iam:PassRole for %s, subject to unevaluated conditions", target)
					finding.Impact = "Effective access cannot be determined without evaluating the condition against runtime context."
					finding.Limitations = []string{conditionReviewNote}
					finding.ChangeUncertain = true
					finding.Remediation = "Review the runtime condition context and restrict PassRole resources to the roles and services required."
				} else {
					finding.Remediation = "Restrict iam:PassRole resources to the required IAM role ARNs and verify which services may receive each role."
				}
				findings = append(findings, finding)
			}
		}
	}
	return findings
}

// DetectAssumeRole reports broad or cross-account AWS trust patterns that can
// be classified from the supported principal forms. Explicit same-account,
// service and federated principals are not treated as suspicious by default.
func DetectAssumeRole(roles []models.Role) []models.Finding {
	findings := []models.Finding{}
	for _, role := range roles {
		for statementIndex, statement := range role.Trust {
			if statement.Effect != "Allow" {
				continue
			}
			for _, principal := range statement.Principals {
				for principalIndex, rawValue := range principal.Values {
					value := strings.TrimSpace(rawValue)
					if value == "" {
						continue
					}
					var finding *models.Finding
					switch principal.Type {
					case "*":
						if value == "*" {
							finding = &models.Finding{
								Severity: "HIGH",
								Title:    "Overly Permissive Trust Policy",
								Role:     role.Name,
								Issue:    "Trust statement allows any principal",
								Impact:   "Any principal may be eligible to assume this role, subject to other AWS authorization controls.",
							}
						}
					case "AWS":
						if value == "*" {
							finding = &models.Finding{
								Severity: "HIGH",
								Title:    "Overly Permissive Trust Policy",
								Role:     role.Name,
								Issue:    "Trust statement allows any AWS principal",
								Impact:   "Any AWS principal may be eligible to assume this role, subject to other AWS authorization controls.",
							}
						} else if isExternalAccountRootPrincipal(value) {
							account := extractAccountFromARN(value)
							if role.AccountID != "" && account != role.AccountID {
								finding = &models.Finding{
									Severity: "HIGH",
									Title:    "External Account Trust Relationship",
									Role:     role.Name,
									Issue:    fmt.Sprintf("Trust statement names external AWS account %s as a principal", account),
									Impact:   "Identities in that account may be eligible to assume this role if their own permissions and any trust conditions allow it.",
									Path:     []string{role.Name, account + ":root"},
								}
							}
						} else if account, ok := awsAccountFromPrincipal(value); ok && role.AccountID != "" && account != role.AccountID {
							finding = &models.Finding{
								Severity: "MEDIUM",
								Title:    "External AWS Principal Trust Relationship",
								Role:     role.Name,
								Issue:    fmt.Sprintf("Trust statement names AWS principal %s from account %s", value, account),
								Impact:   "The named external principal may be eligible to assume this role if its own permissions and any trust conditions allow it.",
							}
						}
					}
					if finding != nil {
						finding.ResourceAddress = statement.Address
						finding.RoleAddress = role.Address
						finding.StatementIndex = intPointer(statementIndex)
						finding.RuleID = ruleIDForTitle(finding.Title)
						finding.IdentityRole = role.AccountID + "|" + role.Name
						finding.IdentitySubject = principal.Type + ":" + value
						finding.IdentityPolicy = statement.Address
						finding.Evidence = models.FindingEvidence{
							RoleReference: role.Name, PolicyReference: statement.Address,
							PrincipalReferences: []string{principal.Type + ":" + value},
							ActionPatterns:      append([]string{}, statement.Actions...), ConditionPresent: len(statement.Condition) > 0,
						}
						finding.MatchKey = findingMatchKey(finding.RuleID, role.Address, statement.Address, statementIndex, principalIndex, principal.Type+":"+value)
						finding.ContextFingerprint = fingerprint(struct {
							RoleName, AccountID              string
							Effect, PrincipalType, Principal string
							Actions                          []string
							Condition                        map[string]map[string]interface{}
						}{role.Name, role.AccountID, statement.Effect, principal.Type, value, statement.Actions, statement.Condition})
						if len(statement.Condition) > 0 {
							finding.Limitations = []string{conditionReviewNote}
							finding.ChangeUncertain = true
						}
						finding.Remediation = "Confirm the trusted account or principal is intended, narrow trust to required principals, and apply appropriate conditions."
						findings = append(findings, *finding)
					}
				}
			}
		}
	}
	return findings
}

func actionsCanMatchPassRole(actions []string) bool {
	for _, action := range actions {
		if iamPatternMatches(action, "iam:PassRole") {
			return true
		}
	}
	return false
}

// IAM action wildcards support '*' (zero or more characters) and '?'
// (one character). Matching is case insensitive. Unlike substring matching,
// this does not treat unrelated prefixes such as "notiam:PassRole" as grants.
func iamPatternMatches(pattern, value string) bool {
	pattern = strings.ToLower(pattern)
	value = strings.ToLower(value)
	previous := make([]bool, len(value)+1)
	previous[0] = true
	for i := 0; i < len(pattern); i++ {
		current := make([]bool, len(value)+1)
		if pattern[i] == '*' {
			current[0] = previous[0]
			for j := 1; j <= len(value); j++ {
				current[j] = previous[j] || current[j-1]
			}
		} else {
			for j := 1; j <= len(value); j++ {
				if pattern[i] == '?' || pattern[i] == value[j-1] {
					current[j] = previous[j-1]
				}
			}
		}
		previous = current
	}
	return previous[len(value)]
}

func isPotentialRoleResource(resource string) bool {
	resource = strings.TrimSpace(resource)
	if resource == "*" {
		return true
	}
	parts := strings.SplitN(resource, ":", 6)
	return len(parts) == 6 && parts[0] == "arn" && parts[2] == "iam" && strings.HasPrefix(parts[5], "role/")
}

func passRoleTarget(resource string) string {
	if resource == "*" {
		return "all IAM roles"
	}
	name := ExtractRoleNameFromARN(resource)
	if name == "" {
		return resource
	}
	return name
}

func isExternalAccountRootPrincipal(principal string) bool {
	parts := strings.Split(principal, ":")
	return len(parts) == 6 && parts[0] == "arn" && parts[2] == "iam" && parts[4] != "" && parts[5] == "root" && isAccountID(parts[4])
}

func awsAccountFromPrincipal(principal string) (string, bool) {
	if isAccountID(principal) {
		return principal, true
	}
	parts := strings.Split(principal, ":")
	if len(parts) == 6 && parts[0] == "arn" && parts[2] == "iam" && isAccountID(parts[4]) {
		return parts[4], true
	}
	return "", false
}

func isAccountID(value string) bool {
	if len(value) != 12 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func extractAccountFromARN(arn string) string {
	if account, ok := awsAccountFromPrincipal(arn); ok {
		return account
	}
	return ""
}

func intPointer(value int) *int { return &value }

func findingMatchKey(ruleID, roleAddress, resourceAddress string, statementIndex, occurrence int, target string) string {
	return fmt.Sprintf("%s|%s|%s|%d|%d|%s", ruleID, roleAddress, resourceAddress, statementIndex, occurrence, target)
}

func fingerprint(value interface{}) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("unavailable:%T", value)
	}
	return string(encoded)
}

func ruleIDForTitle(title string) string {
	switch title {
	case "PassRole Risk Detected":
		return "passrole-risk"
	case "Conditional PassRole Permission Requires Review":
		return "conditional-passrole-review"
	case "External Account Trust Relationship":
		return "external-account-trust"
	case "External AWS Principal Trust Relationship":
		return "external-aws-principal-trust"
	case "Overly Permissive Trust Policy":
		return "overly-permissive-trust"
	default:
		return "iam-trust-risk"
	}
}

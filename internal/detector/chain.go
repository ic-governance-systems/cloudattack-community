package detector

import (
	"fmt"
	"strings"

	"cloudattack-community/internal/models"
)

// DetectChains reports a one-hop potential PassRole/trust pattern. It does
// not establish that the source can invoke a service, that the trust policy
// admits that service in context, or that the target grants greater access.
func DetectChains(roles []models.Role) []models.Finding {
	findings := []models.Finding{}
	seen := map[string]struct{}{}
	for _, source := range roles {
		for _, policy := range source.Policies {
			if policy.Effect != "Allow" || len(policy.Condition) > 0 || !actionsCanMatchPassRole(policy.Actions) {
				continue
			}
			for resourceIndex, resource := range policy.Resources {
				if !isPotentialRoleResource(resource) {
					continue
				}
				for _, target := range roles {
					matches, accountUnknown := resourceMayNameRole(resource, target)
					if !matches || !hasAllowedTrustPrincipal(target.Trust) {
						continue
					}
					key := fmt.Sprintf("%s|%s|%d|%d|%s", source.Address, policy.Address, policy.StatementIndex, resourceIndex, target.Address+"|"+target.Name)
					if _, ok := seen[key]; ok {
						continue
					}
					seen[key] = struct{}{}
					finding := models.Finding{
						RuleID:          "potential-passrole-trust-relationship",
						Severity:        "CRITICAL",
						Title:           "Potential PassRole Trust Relationship",
						Role:            source.Name,
						Issue:           fmt.Sprintf("Role may pass %s, which has an Allow trust statement", target.Name),
						Impact:          "This is a potential one-hop identity-risk pattern; CloudAttack does not prove that the trust relationship is usable or that the target grants greater privilege.",
						Path:            []string{source.Name, target.Name},
						ResourceAddress: policy.Address, RoleAddress: source.Address,
						RelatedAddresses: append([]string{target.Address}, policy.AttachmentAddresses...),
						StatementIndex:   intPointer(policy.StatementIndex),
						IdentityRole:     source.AccountID + "|" + source.Name,
						IdentitySubject:  target.Address + "|" + target.Name,
						IdentityPolicy:   policy.Address,
						Evidence: models.FindingEvidence{
							RoleReference: source.Name, PolicyReference: policy.Address,
							ActionPatterns: append([]string{}, policy.Actions...), ResourcePatterns: []string{resource},
							ConditionPresent: len(policy.Condition) > 0,
						},
					}
					finding.MatchKey = findingMatchKey(finding.RuleID, source.Address, policy.Address, policy.StatementIndex, resourceIndex, target.Address+"|"+target.Name)
					finding.ContextFingerprint = fingerprint(struct {
						SourceName, SourceAccount string
						TargetName, TargetAccount string
						Effect                    string
						Actions, Resources        []string
						SourceConditions          map[string]map[string]interface{}
						TargetTrust               []models.Policy
					}{source.Name, source.AccountID, target.Name, target.AccountID, policy.Effect, policy.Actions, policy.Resources, policy.Condition, target.Trust})
					if trustHasConditions(target.Trust) {
						finding.Limitations = []string{conditionReviewNote}
						finding.ChangeUncertain = true
					}
					if accountUnknown {
						finding.Limitations = append(finding.Limitations, "The target role account ID is unavailable, so CloudAttack cannot confirm that the PassRole resource and target role are in the same account.")
						finding.ChangeUncertain = true
					}
					finding.Remediation = "Review the source role's invocation path, PassRole scope, target trust principals, and target permissions; validate the relationship in its intended runtime context."
					findings = append(findings, finding)
				}
			}
		}
	}
	return findings
}

func trustHasConditions(statements []models.Policy) bool {
	for _, statement := range statements {
		if statement.Effect == "Allow" && len(statement.Condition) > 0 {
			return true
		}
	}
	return false
}

func hasAllowedTrustPrincipal(statements []models.Policy) bool {
	for _, statement := range statements {
		if statement.Effect == "Allow" && len(statement.Principals) > 0 {
			return true
		}
	}
	return false
}

func resourceMayNameRole(resource string, target models.Role) (bool, bool) {
	if resource == "*" {
		return true, false
	}
	roleReference := resource
	accountUnknown := false
	if parts := strings.SplitN(resource, ":", 6); len(parts) == 6 && parts[0] == "arn" && parts[2] == "iam" {
		if target.AccountID != "" && !iamPatternMatches(parts[4], target.AccountID) {
			return false, false
		}
		accountUnknown = target.AccountID == "" && parts[4] != "*"
	}
	if index := strings.LastIndex(resource, ":role/"); index >= 0 {
		roleReference = resource[index+len(":role/"):]
		if slash := strings.LastIndex(roleReference, "/"); slash >= 0 {
			roleReference = roleReference[slash+1:]
		}
	}
	return iamPatternMatches(roleReference, target.Name), accountUnknown
}

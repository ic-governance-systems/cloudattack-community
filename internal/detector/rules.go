package detector

import (
	"fmt"
	"strings"

	"cloudattack-community/internal/models"
)

// DetectPassRole finds iam:PassRole permissions and reports the target role
func DetectPassRole(roles []models.Role) []models.Finding {
	findings := []models.Finding{}
	for _, r := range roles {
		for _, p := range r.Policies {
			for _, a := range p.Actions {
				if strings.EqualFold(a, "iam:passrole") || strings.Contains(strings.ToLower(a), "iam:passrole") {
					// resources may be ARNs or role names
					for _, res := range p.Resources {
						target := ExtractRoleNameFromARN(res)
						if target == "" {
							target = res
						}
						findings = append(findings, models.Finding{
							Severity: "CRITICAL",
							Title:    "PassRole Risk Detected",
							Role:     r.Name,
							Issue:    fmt.Sprintf("Can pass role %s", target),
							Impact:   "May enable privilege escalation into higher privilege role",
						})
					}
				}
			}
		}
	}
	return findings
}

// DetectAssumeRole inspects trust relationships
func DetectAssumeRole(roles []models.Role) []models.Finding {
	findings := []models.Finding{}
	for _, r := range roles {
		if len(r.Trust) == 0 {
			continue
		}
		for _, t := range r.Trust {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}

			// Ignore common AWS service principals (normal behavior)
			if isAWSServicePrincipal(t) {
				continue
			}

			if t == "*" || t == "arn:aws:iam:::*" {
				findings = append(findings, models.Finding{
					Severity: "HIGH",
					Title:    "Open Trust Policy",
					Role:     r.Name,
					Issue:    "Trusts ANY principal",
					Impact:   "Any AWS identity may assume this role",
				})
			} else if isExternalAccountRootPrincipal(t) {
				account := extractAccountFromARN(t)
				if r.AccountID != "" && account == r.AccountID {
					continue
				}
				findings = append(findings, models.Finding{
					Severity: "HIGH",
					Title:    "External Account Trust Relationship",
					Role:     r.Name,
					Issue:    fmt.Sprintf("External AWS account %s can assume this role via root trust", account),
					Impact:   "External AWS account can assume this role and inherit its permissions",
					Path:     []string{r.Name, account + ":root"},
				})
			} else if t != "" {
				findings = append(findings, models.Finding{
					Severity: "MEDIUM",
					Title:    "Suspicious Trust Relationship",
					Role:     r.Name,
					Issue:    fmt.Sprintf("Suspicious principal %s can assume role %s", t, r.Name),
					Impact:   "Unusual or unknown principal configured in trust policy",
				})
			}
		}
	}
	return findings
}

// isAWSServicePrincipal returns true for common AWS service principals
func isAWSServicePrincipal(principal string) bool {
	if principal == "" {
		return false
	}
	// service principals typically end with .amazonaws.com
	if strings.HasSuffix(principal, ".amazonaws.com") {
		return true
	}
	return false
}

func isExternalAccountRootPrincipal(principal string) bool {
	if !strings.HasPrefix(principal, "arn:aws:iam::") {
		return false
	}
	if !strings.HasSuffix(principal, ":root") {
		return false
	}
	account := extractAccountFromARN(principal)
	if account == "" {
		return false
	}
	for _, ch := range account {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func extractAccountFromARN(arn string) string {
	// expects formats like arn:aws:iam::123456789012:root or arn:aws:iam::123456789012:role/Name
	const prefix = "arn:aws:iam::"
	if !strings.HasPrefix(arn, prefix) {
		return arn
	}
	rest := strings.TrimPrefix(arn, prefix)
	// rest starts with account id
	// find next ':' or '/'
	for i, ch := range rest {
		if ch == ':' || ch == '/' {
			return rest[:i]
		}
	}
	return rest
}

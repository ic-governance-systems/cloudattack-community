package detector

import (
	"fmt"
	"strings"

	"cloudattack-community/internal/models"
)

// DetectChains finds simple 1-hop privilege escalation chains: Role A can PassRole -> Role B, and Role B has trust relationships
func DetectChains(roles []models.Role) []models.Finding {
	findings := []models.Finding{}

	// build lookup map for roles by name
	roleMap := map[string]models.Role{}
	for _, r := range roles {
		roleMap[r.Name] = r
	}

	seen := map[string]struct{}{}

	for _, a := range roles { // source role
		for _, p := range a.Policies {
			for _, act := range p.Actions {
				if act == "" {
					continue
				}
				if containsIgnoreCase(act, "iam:passrole") {
					// for each resource, extract target role
					for _, res := range p.Resources {
						target := ExtractRoleNameFromARN(res)
						if target == "" {
							target = res
						}
						// check target exists
						if b, ok := roleMap[target]; ok {
							// ensure target has trust relationships (non-empty and not only service principals)
							if len(b.Trust) == 0 {
								continue
							}

							// prepare finding
							pathKey := fmt.Sprintf("%s->%s", a.Name, b.Name)
							if _, ok := seen[pathKey]; ok {
								continue
							}
							seen[pathKey] = struct{}{}

							f := models.Finding{
								Severity: "CRITICAL",
								Title:    "Privilege Escalation Path Detected",
								Role:     a.Name,
								Issue:    fmt.Sprintf("Can pass role %s which has trust relationships", b.Name),
								Impact:   "This chain may allow privilege escalation across roles",
								Path:     []string{a.Name, b.Name},
							}
							findings = append(findings, f)
						}
					}
				}
			}
		}
	}

	return findings
}

// containsIgnoreCase checks substring case-insensitively
func containsIgnoreCase(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

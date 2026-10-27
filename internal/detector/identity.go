package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"cloudattack-community/internal/models"
)

const findingIdentityVersion = "cloudattack-finding-v1"

// AssignFindingIdentities adds deterministic instance IDs without using scan
// metadata or statement indexes. Colliding logical anchors are left without a
// definitive ID and marked ambiguous.
func AssignFindingIdentities(findings []models.Finding, plan models.TerraformPlan) {
	type identity struct {
		RuleID, Role, Resource, Subject string
		Ambiguous                       bool
	}
	identities := make([]identity, len(findings))
	counts := map[string]int{}
	encoded := make([]string, len(findings))
	for i, finding := range findings {
		role, roleAmbiguous := canonicalIdentityAddress(finding.RoleAddress, plan)
		resource, resourceAmbiguous := canonicalIdentityAddress(finding.ResourceAddress, plan)
		if role == "" {
			role = finding.IdentityRole
		}
		if resource == "" {
			resource = finding.IdentityPolicy
		}
		id := identity{RuleID: finding.RuleID, Role: role, Resource: resource, Subject: finding.IdentitySubject, Ambiguous: roleAmbiguous || resourceAmbiguous}
		identities[i] = id
		if id.RuleID == "" || (id.Role == "" && id.Resource == "") || id.Ambiguous {
			continue
		}
		value, err := json.Marshal(struct {
			Version  string `json:"version"`
			RuleID   string `json:"rule_id"`
			Role     string `json:"role"`
			Resource string `json:"resource"`
			Subject  string `json:"subject"`
		}{findingIdentityVersion, id.RuleID, id.Role, id.Resource, id.Subject})
		if err != nil {
			continue
		}
		encoded[i] = string(value)
		counts[encoded[i]]++
	}
	for i := range findings {
		findings[i].FindingID = ""
		findings[i].IdentityStatus = "ambiguous"
		if encoded[i] == "" || identities[i].Ambiguous || counts[encoded[i]] != 1 {
			continue
		}
		digest := sha256.Sum256([]byte(encoded[i]))
		findings[i].FindingID = "caf1_" + hex.EncodeToString(digest[:])
		findings[i].IdentityStatus = "stable"
	}
}

func canonicalIdentityAddress(address string, plan models.TerraformPlan) (string, bool) {
	if address == "" {
		return "", false
	}
	var previous string
	count := 0
	for _, change := range plan.Changes {
		if change.Address == address && change.PreviousAddress != "" {
			previous = change.PreviousAddress
			count++
		}
	}
	if count > 1 {
		return "", true
	}
	if count == 1 {
		aliases := 0
		for _, change := range plan.Changes {
			if change.PreviousAddress == previous {
				aliases++
			}
		}
		if aliases != 1 {
			return "", true
		}
		return previous, false
	}
	return address, false
}

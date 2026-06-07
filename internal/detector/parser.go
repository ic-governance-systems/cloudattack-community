package detector

import (
	"encoding/json"
	"strings"

	"cloudattack-community/internal/models"
)

// ParseIAM parses the output of `aws iam get-account-authorization-details` and
// returns a slice of models.Role representing roles, their inline policies and trust principals.
func ParseIAM(data []byte) []models.Role {
	var top map[string]interface{}
	if err := json.Unmarshal(data, &top); err != nil {
		// try to unmarshal as array of roles directly
		var arr []interface{}
		if err2 := json.Unmarshal(data, &arr); err2 == nil {
			// wrap into top
			top = map[string]interface{}{"RoleDetailList": arr}
		} else {
			return nil
		}
	}

	roles := []models.Role{}

	rlist, ok := top["RoleDetailList"].([]interface{})
	if !ok {
		return roles
	}

	for _, ri := range rlist {
		rmap, ok := ri.(map[string]interface{})
		if !ok {
			continue
		}

		name, _ := rmap["RoleName"].(string)
		role := models.Role{Name: name}
		if arn, _ := rmap["Arn"].(string); arn != "" {
			role.AccountID = extractAccountFromARN(arn)
		}

		// Parse assume role policy (trust)
		trusts := []string{}
		if arb, ok := rmap["AssumeRolePolicyDocument"]; ok {
			var doc map[string]interface{}
			switch v := arb.(type) {
			case string:
				// sometimes it's a JSON-encoded string
				_ = json.Unmarshal([]byte(v), &doc)
			case map[string]interface{}:
				doc = v
			}

			if doc != nil {
				stmts := normalizeStatements(doc["Statement"])
				for _, s := range stmts {
					if p := extractPrincipalsFromStatement(s); len(p) > 0 {
						trusts = append(trusts, p...)
					}
				}
			}
		}
		// dedupe trusts
		role.Trust = uniqueStrings(trusts)

		// Parse inline policies (RolePolicyList)
		policies := []models.Policy{}
		if rpols, ok := rmap["RolePolicyList"].([]interface{}); ok {
			for _, p := range rpols {
				pmap, ok := p.(map[string]interface{})
				if !ok {
					continue
				}
				var doc map[string]interface{}
				if pd, ok := pmap["PolicyDocument"]; ok {
					switch v := pd.(type) {
					case string:
						_ = json.Unmarshal([]byte(v), &doc)
					case map[string]interface{}:
						doc = v
					}
				}

				if doc == nil {
					continue
				}

				stmts := normalizeStatements(doc["Statement"])
				for _, s := range stmts {
					actions := toStringSlice(s["Action"])
					resources := toStringSlice(s["Resource"])
					if len(actions) == 0 && len(resources) == 0 {
						continue
					}
					policies = append(policies, models.Policy{Actions: actions, Resources: resources})
				}
			}
		}
		role.Policies = policies

		roles = append(roles, role)
	}

	return roles
}

func normalizeStatements(raw interface{}) []map[string]interface{} {
	stmts := []map[string]interface{}{}
	if raw == nil {
		return stmts
	}
	switch s := raw.(type) {
	case []interface{}:
		for _, si := range s {
			if sm, ok := si.(map[string]interface{}); ok {
				stmts = append(stmts, sm)
			}
		}
	case map[string]interface{}:
		stmts = append(stmts, s)
	}
	return stmts
}

func extractPrincipalsFromStatement(stmt map[string]interface{}) []string {
	out := []string{}
	if stmt == nil {
		return out
	}
	if p, ok := stmt["Principal"]; ok {
		switch v := p.(type) {
		case string:
			out = append(out, v)
		case map[string]interface{}:
			for _, val := range v {
				switch vv := val.(type) {
				case string:
					out = append(out, vv)
				case []interface{}:
					for _, e := range vv {
						if s, ok := e.(string); ok {
							out = append(out, s)
						}
					}
				}
			}
		}
	}
	return out
}

func toStringSlice(v interface{}) []string {
	out := []string{}
	if v == nil {
		return out
	}
	switch t := v.(type) {
	case string:
		if t != "" {
			out = append(out, t)
		}
	case []interface{}:
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// helper to extract role name from ARN-ish resource
func roleNameFromARN(arn string) string {
	if arn == "" {
		return ""
	}
	// look for :role/ or /role/
	if idx := strings.LastIndex(arn, ":role/"); idx != -1 {
		return arn[idx+6:]
	}
	if idx := strings.LastIndex(arn, "/"); idx != -1 {
		return arn[idx+1:]
	}
	return arn
}

// Export helper used by rules
func ExtractRoleNameFromARN(arn string) string {
	return roleNameFromARN(arn)
}

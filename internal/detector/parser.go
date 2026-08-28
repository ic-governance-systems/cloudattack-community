package detector

import (
	"encoding/json"
	"fmt"
	"strings"

	"cloudattack-community/internal/models"
)

// ParseIAM parses the output of `aws iam get-account-authorization-details` and
// returns a slice of models.Role representing roles, their inline policies and trust principals.
func ParseIAM(data []byte) ([]models.Role, error) {
	var raw interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	var roleData []interface{}
	switch value := raw.(type) {
	case []interface{}:
		roleData = value
	case map[string]interface{}:
		var ok bool
		if roleData, ok = value["RoleDetailList"].([]interface{}); !ok {
			if _, exists := value["RoleDetailList"]; exists {
				return nil, fmt.Errorf("RoleDetailList must be an array")
			}
			if roleData, ok = value["Roles"].([]interface{}); !ok {
				if _, exists := value["Roles"]; exists {
					return nil, fmt.Errorf("Roles must be an array")
				}
				return nil, fmt.Errorf("unsupported IAM input: expected RoleDetailList or Roles")
			}
		}
	default:
		return nil, fmt.Errorf("unsupported IAM input: expected an object or array of roles")
	}

	if err := validateRoles(roleData); err != nil {
		return nil, err
	}

	top := map[string]interface{}{"RoleDetailList": roleData}

	roles := []models.Role{}

	rlist, ok := top["RoleDetailList"].([]interface{})
	if !ok {
		return roles, nil
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

	return roles, nil
}

func validateRoles(roles []interface{}) error {
	for i, value := range roles {
		role, ok := value.(map[string]interface{})
		if !ok {
			return fmt.Errorf("role at index %d must be an object", i)
		}
		name, exists := role["RoleName"]
		if !exists {
			return fmt.Errorf("role at index %d is missing RoleName", i)
		}
		if _, ok := name.(string); !ok {
			return fmt.Errorf("role at index %d RoleName must be a string", i)
		}
		if arn, exists := role["Arn"]; exists {
			if _, ok := arn.(string); !ok {
				return fmt.Errorf("role %d Arn must be a string", i)
			}
		}
		if policies, exists := role["RolePolicyList"]; exists {
			list, ok := policies.([]interface{})
			if !ok {
				return fmt.Errorf("role %d RolePolicyList must be an array", i)
			}
			if err := validatePolicies(list, i); err != nil {
				return err
			}
		}
		if trust, exists := role["AssumeRolePolicyDocument"]; exists {
			if err := validatePolicyDocument(trust, fmt.Sprintf("role %d AssumeRolePolicyDocument", i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func validatePolicies(policies []interface{}, roleIndex int) error {
	for i, value := range policies {
		policy, ok := value.(map[string]interface{})
		if !ok {
			return fmt.Errorf("role %d policy %d must be an object", roleIndex, i)
		}
		document, exists := policy["PolicyDocument"]
		if !exists {
			return fmt.Errorf("role %d policy %d is missing PolicyDocument", roleIndex, i)
		}
		if err := validatePolicyDocument(document, fmt.Sprintf("role %d policy %d PolicyDocument", roleIndex, i)); err != nil {
			return err
		}
	}
	return nil
}

func validatePolicyDocument(value interface{}, path string) error {
	var document map[string]interface{}
	switch typed := value.(type) {
	case string:
		if err := json.Unmarshal([]byte(typed), &document); err != nil {
			return fmt.Errorf("%s contains invalid JSON: %w", path, err)
		}
	case map[string]interface{}:
		document = typed
	default:
		return fmt.Errorf("%s must be an object or JSON string", path)
	}
	if document == nil {
		return fmt.Errorf("%s must contain a JSON object", path)
	}

	if statements, exists := document["Statement"]; exists {
		if err := validateStatements(statements, path+".Statement"); err != nil {
			return err
		}
	}
	return nil
}

func validateStatements(value interface{}, path string) error {
	values := []interface{}{value}
	if list, ok := value.([]interface{}); ok {
		values = list
	} else if _, ok := value.(map[string]interface{}); !ok {
		return fmt.Errorf("%s must be an object or array", path)
	}

	for i, value := range values {
		statement, ok := value.(map[string]interface{})
		if !ok {
			return fmt.Errorf("%s[%d] must be an object", path, i)
		}
		if err := validateStringOrStringArray(statement, "Action", path, i); err != nil {
			return err
		}
		if err := validateStringOrStringArray(statement, "Resource", path, i); err != nil {
			return err
		}
		if principal, exists := statement["Principal"]; exists {
			if err := validatePrincipal(principal, fmt.Sprintf("%s[%d].Principal", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateStringOrStringArray(statement map[string]interface{}, field, path string, index int) error {
	value, exists := statement[field]
	if !exists {
		return nil
	}
	switch typed := value.(type) {
	case string:
		return nil
	case []interface{}:
		for j, item := range typed {
			if _, ok := item.(string); !ok {
				return fmt.Errorf("%s[%d].%s[%d] must be a string", path, index, field, j)
			}
		}
		return nil
	default:
		return fmt.Errorf("%s[%d].%s must be a string or array", path, index, field)
	}
}

func validatePrincipal(value interface{}, path string) error {
	switch typed := value.(type) {
	case string:
		return nil
	case map[string]interface{}:
		for key, item := range typed {
			switch principals := item.(type) {
			case string:
			case []interface{}:
				for i, principal := range principals {
					if _, ok := principal.(string); !ok {
						return fmt.Errorf("%s.%s[%d] must be a string", path, key, i)
					}
				}
			default:
				return fmt.Errorf("%s.%s must be a string or array", path, key)
			}
		}
		return nil
	default:
		return fmt.Errorf("%s must be a string or object", path)
	}
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

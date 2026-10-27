package detector

import (
	"encoding/json"
	"fmt"
	"sort"
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

		// Keep trust statements intact. Flattening principals loses Effect,
		// Principal type and conditions, which are needed to interpret trust.
		trusts := []models.Policy{}
		if arb, ok := rmap["AssumeRolePolicyDocument"]; ok {
			doc, err := decodePolicyDocument(arb)
			if err != nil {
				return nil, fmt.Errorf("role %q trust policy: %w", role.Name, err)
			}
			trusts, err = parseStatements(doc["Statement"], true)
			if err != nil {
				return nil, fmt.Errorf("role %q trust policy: %w", role.Name, err)
			}
		}
		role.Trust = trusts

		// Parse inline policies (RolePolicyList)
		policies := []models.Policy{}
		if rpols, ok := rmap["RolePolicyList"].([]interface{}); ok {
			for _, p := range rpols {
				pmap, ok := p.(map[string]interface{})
				if !ok {
					continue
				}
				if pd, ok := pmap["PolicyDocument"]; ok {
					doc, err := decodePolicyDocument(pd)
					if err != nil {
						return nil, fmt.Errorf("role %q policy: %w", role.Name, err)
					}
					statements, err := parseStatements(doc["Statement"], false)
					if err != nil {
						return nil, fmt.Errorf("role %q policy: %w", role.Name, err)
					}
					policies = append(policies, statements...)
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
			if err := validatePolicyDocument(trust, fmt.Sprintf("role %d AssumeRolePolicyDocument", i), true); err != nil {
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
		if err := validatePolicyDocument(document, fmt.Sprintf("role %d policy %d PolicyDocument", roleIndex, i), false); err != nil {
			return err
		}
	}
	return nil
}

func decodePolicyDocument(value interface{}) (map[string]interface{}, error) {
	var document map[string]interface{}
	switch typed := value.(type) {
	case string:
		if err := json.Unmarshal([]byte(typed), &document); err != nil {
			return nil, fmt.Errorf("contains invalid JSON: %w", err)
		}
	case map[string]interface{}:
		document = typed
	default:
		return nil, fmt.Errorf("must be an object or JSON string")
	}
	if document == nil {
		return nil, fmt.Errorf("must contain a JSON object")
	}
	return document, nil
}

func validatePolicyDocument(value interface{}, path string, trust bool) error {
	document, err := decodePolicyDocument(value)
	if err != nil {
		return fmt.Errorf("%s %w", path, err)
	}
	statements, exists := document["Statement"]
	if !exists {
		return fmt.Errorf("%s.Statement is required", path)
	}
	return validateStatements(statements, path+".Statement", trust)
}

func validateStatements(value interface{}, path string, trust bool) error {
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
		effect, ok := statement["Effect"].(string)
		if !ok || (effect != "Allow" && effect != "Deny") {
			return fmt.Errorf("%s[%d].Effect must be Allow or Deny", path, i)
		}
		if _, exists := statement["NotAction"]; exists {
			return fmt.Errorf("%s[%d].NotAction is unsupported", path, i)
		}
		if _, exists := statement["NotResource"]; exists {
			return fmt.Errorf("%s[%d].NotResource is unsupported", path, i)
		}
		if _, exists := statement["NotPrincipal"]; exists {
			return fmt.Errorf("%s[%d].NotPrincipal is unsupported", path, i)
		}
		if _, exists := statement["Action"]; !exists {
			return fmt.Errorf("%s[%d].Action is required", path, i)
		}
		if !trust {
			if _, exists := statement["Resource"]; !exists {
				return fmt.Errorf("%s[%d].Resource is required", path, i)
			}
			if _, exists := statement["Principal"]; exists {
				return fmt.Errorf("%s[%d].Principal is unsupported in role identity policies", path, i)
			}
		}
		if principal, exists := statement["Principal"]; exists {
			if err := validatePrincipal(principal, fmt.Sprintf("%s[%d].Principal", path, i)); err != nil {
				return err
			}
		} else if trust {
			return fmt.Errorf("%s[%d].Principal is required in a trust policy", path, i)
		}
		if condition, exists := statement["Condition"]; exists {
			if err := validateCondition(condition, fmt.Sprintf("%s[%d].Condition", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateCondition(value interface{}, path string) error {
	operators, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("%s must be an object", path)
	}
	for operator, rawEntries := range operators {
		if operator == "" {
			return fmt.Errorf("%s contains an empty operator", path)
		}
		entries, ok := rawEntries.(map[string]interface{})
		if !ok || len(entries) == 0 {
			return fmt.Errorf("%s.%s must be an object", path, operator)
		}
		for key, rawValue := range entries {
			if key == "" || !validConditionValue(rawValue) {
				return fmt.Errorf("%s.%s.%s has an unsupported value", path, operator, key)
			}
		}
	}
	return nil
}

func parseStatements(value interface{}, trust bool) ([]models.Policy, error) {
	values := []interface{}{value}
	if list, ok := value.([]interface{}); ok {
		values = list
	}
	statements := make([]models.Policy, 0, len(values))
	for i, raw := range values {
		statement, ok := raw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("Statement[%d] must be an object", i)
		}
		policy := models.Policy{
			Effect:    statement["Effect"].(string),
			Actions:   toStringSlice(statement["Action"]),
			Resources: toStringSlice(statement["Resource"]),
			StatementIndex: i,
		}
		if rawCondition, exists := statement["Condition"]; exists {
			condition := rawCondition.(map[string]interface{})
			policy.Condition = make(map[string]map[string]interface{}, len(condition))
			for operator, rawEntries := range condition {
				entries := rawEntries.(map[string]interface{})
				policy.Condition[operator] = entries
			}
		}
		if trust {
			principals, err := parsePrincipals(statement["Principal"])
			if err != nil {
				return nil, fmt.Errorf("Statement[%d].Principal: %w", i, err)
			}
			policy.Principals = principals
		}
		statements = append(statements, policy)
	}
	return statements, nil
}

func parsePrincipals(value interface{}) ([]models.Principal, error) {
	if direct, ok := value.(string); ok {
		if strings.HasPrefix(direct, "arn:aws:iam::") || isAccountID(direct) {
			return []models.Principal{{Type: "AWS", Values: []string{direct}}}, nil
		}
		return []models.Principal{{Type: "*", Values: []string{direct}}}, nil
	}
	principalMap, ok := value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("must be a string or object")
	}
	types := make([]string, 0, len(principalMap))
	for principalType := range principalMap {
		types = append(types, principalType)
	}
	sort.Strings(types)
	principals := make([]models.Principal, 0, len(types))
	for _, principalType := range types {
		values := toStringSlice(principalMap[principalType])
		principals = append(principals, models.Principal{Type: principalType, Values: values})
	}
	return principals, nil
}

func validConditionValue(value interface{}) bool {
	switch typed := value.(type) {
	case string, bool, float64:
		return true
	case []interface{}:
		if len(typed) == 0 {
			return false
		}
		for _, item := range typed {
			if text, ok := item.(string); !ok || text == "" {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func validateStringOrStringArray(statement map[string]interface{}, field, path string, index int) error {
	value, exists := statement[field]
	if !exists {
		return nil
	}
	switch typed := value.(type) {
	case string:
		if typed == "" {
			return fmt.Errorf("%s[%d].%s must not be empty", path, index, field)
		}
		return nil
	case []interface{}:
		if len(typed) == 0 {
			return fmt.Errorf("%s[%d].%s must not be empty", path, index, field)
		}
		for j, item := range typed {
			if text, ok := item.(string); !ok || text == "" {
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
		if typed == "" {
			return fmt.Errorf("%s must not be empty", path)
		}
		return nil
	case map[string]interface{}:
		for key, item := range typed {
			if key == "" {
				return fmt.Errorf("%s contains an empty principal type", path)
			}
			switch principals := item.(type) {
			case string:
				if principals == "" {
					return fmt.Errorf("%s.%s must not be empty", path, key)
				}
			case []interface{}:
				if len(principals) == 0 {
					return fmt.Errorf("%s.%s must not be empty", path, key)
				}
				for i, principal := range principals {
					if text, ok := principal.(string); !ok || text == "" {
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

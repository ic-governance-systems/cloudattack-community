package input

import (
	"encoding/json"
	"fmt"

	"cloudattack-community/internal/detector"
	"cloudattack-community/internal/models"
)

const (
	SourceIAM           = "aws-iam-json"
	SourceTerraformPlan = "terraform-plan"
)

// Parse normalizes a supported input source into the canonical detector model.
func Parse(source string, data []byte) ([]models.Role, error) {
	switch source {
	case SourceIAM:
		return detector.ParseIAM(data)
	case SourceTerraformPlan:
		return parseTerraformPlan(data)
	default:
		return nil, fmt.Errorf("unsupported input source %q", source)
	}
}

// ParseSource is the source-dispatching entry point used by the CLI.
func ParseSource(source string, data []byte) ([]models.Role, error) {
	return Parse(source, data)
}

func parseTerraformPlan(data []byte) ([]models.Role, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid Terraform plan JSON: %w", err)
	}

	formatVersion, ok := raw["format_version"]
	if !ok {
		return nil, fmt.Errorf("unsupported Terraform input: missing format_version")
	}
	var version string
	if err := json.Unmarshal(formatVersion, &version); err != nil || version == "" {
		return nil, fmt.Errorf("Terraform format_version must be a non-empty string")
	}
	resourceChangesRaw, ok := raw["resource_changes"]
	if !ok {
		return nil, fmt.Errorf("unsupported Terraform input: missing resource_changes")
	}
	if string(resourceChangesRaw) == "null" {
		return nil, fmt.Errorf("Terraform resource_changes must be an array")
	}
	var changes []json.RawMessage
	if err := json.Unmarshal(resourceChangesRaw, &changes); err != nil {
		return nil, fmt.Errorf("Terraform resource_changes must be an array")
	}

	roles := make([]models.Role, 0)
	roleIndexes := make(map[string]int)
	roleAddresses := make(map[string]string)
	managedPolicies := make(map[string][]models.Policy)
	attachments := make([]terraformAttachment, 0)

	for i, changeRaw := range changes {
		change, err := decodeResourceChange(changeRaw, i)
		if err != nil {
			return nil, err
		}
		if !isSupportedTerraformType(change.Type) {
			continue
		}
		if err := validateChange(change, i); err != nil {
			return nil, err
		}
		if isDeleteOnly(change.Actions) {
			continue
		}

		switch change.Type {
		case "aws_iam_role":
			role, err := parseTerraformRole(change, i)
			if err != nil {
				return nil, err
			}
			if _, exists := roleIndexes[role.Name]; exists {
				return nil, fmt.Errorf("Terraform resource %q duplicates IAM role %q", change.Address, role.Name)
			}
			roleIndexes[role.Name] = len(roles)
			roleAddresses[change.Address] = role.Name
			roles = append(roles, role)
		case "aws_iam_role_policy":
			roleName, policies, err := parseTerraformRolePolicy(change, i)
			if err != nil {
				return nil, err
			}
			attachments = append(attachments, terraformAttachment{role: roleName, policies: policies})
		case "aws_iam_policy":
			keys, policies, err := parseTerraformManagedPolicy(change, i)
			if err != nil {
				return nil, err
			}
			for _, key := range keys {
				managedPolicies[key] = policies
			}
		case "aws_iam_role_policy_attachment":
			attachment, err := parseTerraformRolePolicyAttachment(change, i)
			if err != nil {
				return nil, err
			}
			attachments = append(attachments, attachment)
		case "aws_iam_policy_attachment":
			parsed, err := parseTerraformPolicyAttachment(change, i)
			if err != nil {
				return nil, err
			}
			attachments = append(attachments, parsed...)
		}
	}

	for _, attachment := range attachments {
		if attachment.policyARN != "" {
			policies, ok := managedPolicies[attachment.policyARN]
			if !ok {
				return nil, fmt.Errorf("Terraform attachment references unresolved IAM policy %q", attachment.policyARN)
			}
			attachment.policies = policies
		}
		for _, roleReference := range attachment.roles() {
			roleName, ok := resolveRoleReference(roleReference, roleIndexes, roleAddresses)
			if !ok {
				return nil, fmt.Errorf("Terraform attachment references unresolved IAM role %q", roleReference)
			}
			roles[roleIndexes[roleName]].Policies = append(roles[roleIndexes[roleName]].Policies, attachment.policies...)
		}
	}

	return roles, nil
}

type terraformResourceChange struct {
	Address      string
	Type         string
	Actions      []string
	After        map[string]json.RawMessage
	AfterUnknown map[string]json.RawMessage
}

type terraformAttachment struct {
	role      string
	roleList  []string
	policyARN string
	policies  []models.Policy
}

func (a terraformAttachment) roles() []string {
	if a.role != "" {
		return []string{a.role}
	}
	return a.roleList
}

func decodeResourceChange(raw json.RawMessage, index int) (terraformResourceChange, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return terraformResourceChange{}, fmt.Errorf("Terraform resource_changes[%d] must be an object", index)
	}
	var change terraformResourceChange
	if err := unmarshalString(object, "address", &change.Address); err != nil {
		return terraformResourceChange{}, fmt.Errorf("Terraform resource_changes[%d] address must be a string", index)
	}
	if err := unmarshalString(object, "type", &change.Type); err != nil || change.Type == "" {
		return terraformResourceChange{}, fmt.Errorf("Terraform resource_changes[%d] type must be a non-empty string", index)
	}
	changeRaw, ok := object["change"]
	if !ok {
		return change, nil
	}
	var changeObject map[string]json.RawMessage
	if err := json.Unmarshal(changeRaw, &changeObject); err != nil {
		return terraformResourceChange{}, fmt.Errorf("Terraform resource %q change must be an object", change.Address)
	}
	if actionsRaw, ok := changeObject["actions"]; ok {
		if err := json.Unmarshal(actionsRaw, &change.Actions); err != nil {
			return terraformResourceChange{}, fmt.Errorf("Terraform resource %q change.actions must be an array", change.Address)
		}
	}
	if afterRaw, ok := changeObject["after"]; ok && string(afterRaw) != "null" {
		if err := json.Unmarshal(afterRaw, &change.After); err != nil {
			return terraformResourceChange{}, fmt.Errorf("Terraform resource %q change.after must be an object", change.Address)
		}
	}
	if unknownRaw, ok := changeObject["after_unknown"]; ok && string(unknownRaw) != "null" {
		if err := json.Unmarshal(unknownRaw, &change.AfterUnknown); err != nil {
			return terraformResourceChange{}, fmt.Errorf("Terraform resource %q change.after_unknown must be an object", change.Address)
		}
	}
	return change, nil
}

func validateChange(change terraformResourceChange, index int) error {
	if len(change.Actions) == 0 {
		return fmt.Errorf("Terraform resource %q change.actions must be a non-empty array", change.Address)
	}
	if isDeleteOnly(change.Actions) {
		return nil
	}
	if change.After == nil {
		return fmt.Errorf("Terraform resource %q has no planned after value", change.Address)
	}
	_ = index
	return nil
}

func parseTerraformRole(change terraformResourceChange, index int) (models.Role, error) {
	name, err := requiredString(change, "name", index)
	if err != nil {
		return models.Role{}, err
	}
	trust, err := requiredDocument(change, "assume_role_policy", index)
	if err != nil {
		return models.Role{}, err
	}
	parsed, err := parseSyntheticRole(name, trust, nil)
	if err != nil {
		return models.Role{}, fmt.Errorf("Terraform resource %q trust policy: %w", change.Address, err)
	}
	if arn, ok := optionalString(change.After, "arn"); ok {
		parsed.AccountID = extractAccountFromARN(arn)
	}
	return parsed, nil
}

func parseTerraformRolePolicy(change terraformResourceChange, index int) (string, []models.Policy, error) {
	role, err := requiredString(change, "role", index)
	if err != nil {
		return "", nil, err
	}
	document, err := requiredDocument(change, "policy", index)
	if err != nil {
		return "", nil, err
	}
	parsed, err := parseSyntheticRole("terraform-inline-policy", nil, document)
	if err != nil {
		return "", nil, fmt.Errorf("Terraform resource %q policy: %w", change.Address, err)
	}
	return role, parsed.Policies, nil
}

func parseTerraformManagedPolicy(change terraformResourceChange, index int) ([]string, []models.Policy, error) {
	document, err := requiredDocument(change, "policy", index)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := parseSyntheticRole("terraform-managed-policy", nil, document)
	if err != nil {
		return nil, nil, fmt.Errorf("Terraform resource %q policy: %w", change.Address, err)
	}
	keys := make([]string, 0, 2)
	for _, field := range []string{"arn", "id"} {
		if value, ok := optionalString(change.After, field); ok && value != "" {
			keys = append(keys, value)
		}
	}
	if len(keys) == 0 {
		// The policy can still be parsed safely. An attachment that needs this
		// policy will fail explicitly during relationship resolution.
		return nil, parsed.Policies, nil
	}
	return keys, parsed.Policies, nil
}

func parseTerraformRolePolicyAttachment(change terraformResourceChange, index int) (terraformAttachment, error) {
	role, err := requiredString(change, "role", index)
	if err != nil {
		return terraformAttachment{}, err
	}
	policyARN, err := requiredString(change, "policy_arn", index)
	if err != nil {
		return terraformAttachment{}, err
	}
	return terraformAttachment{role: role, policyARN: policyARN}, nil
}

func parseTerraformPolicyAttachment(change terraformResourceChange, index int) ([]terraformAttachment, error) {
	if isUnknown(change.AfterUnknown, "roles") {
		return nil, fmt.Errorf("Terraform resource %q required IAM field %q is unknown", change.Address, "roles")
	}
	roles, exists := change.After["roles"]
	if !exists {
		return nil, nil
	}
	if string(roles) == "null" {
		return nil, fmt.Errorf("Terraform resource %q roles must be an array of strings", change.Address)
	}
	var roleList []string
	if err := json.Unmarshal(roles, &roleList); err != nil {
		return nil, fmt.Errorf("Terraform resource %q roles must be an array of strings", change.Address)
	}
	if len(roleList) == 0 {
		return nil, nil
	}
	policyARN, err := requiredString(change, "policy_arn", index)
	if err != nil {
		return nil, err
	}
	return []terraformAttachment{{roleList: roleList, policyARN: policyARN}}, nil
}

func requiredString(change terraformResourceChange, field string, index int) (string, error) {
	if isUnknown(change.AfterUnknown, field) {
		return "", fmt.Errorf("Terraform resource %q required IAM field %q is unknown", change.Address, field)
	}
	value, ok := change.After[field]
	if !ok {
		return "", fmt.Errorf("Terraform resource %q is missing required IAM field %q", change.Address, field)
	}
	var result string
	if err := json.Unmarshal(value, &result); err != nil || result == "" {
		return "", fmt.Errorf("Terraform resource %q IAM field %q must be a non-empty string", change.Address, field)
	}
	_ = index
	return result, nil
}

func requiredDocument(change terraformResourceChange, field string, index int) (json.RawMessage, error) {
	if isUnknown(change.AfterUnknown, field) {
		return nil, fmt.Errorf("Terraform resource %q required IAM field %q is unknown", change.Address, field)
	}
	document, ok := change.After[field]
	if !ok || string(document) == "null" {
		return nil, fmt.Errorf("Terraform resource %q is missing required IAM field %q", change.Address, field)
	}
	var value interface{}
	if err := json.Unmarshal(document, &value); err != nil {
		return nil, fmt.Errorf("Terraform resource %q IAM field %q is invalid JSON", change.Address, field)
	}
	if _, ok := value.(string); !ok {
		if _, ok := value.(map[string]interface{}); !ok {
			return nil, fmt.Errorf("Terraform resource %q IAM field %q must be a JSON string or object", change.Address, field)
		}
	}
	_ = index
	return document, nil
}

func parseSyntheticRole(name string, trust, policy json.RawMessage) (models.Role, error) {
	role := map[string]interface{}{"RoleName": name}
	if trust != nil {
		role["AssumeRolePolicyDocument"] = trust
	}
	if policy != nil {
		role["RolePolicyList"] = []interface{}{map[string]interface{}{"PolicyDocument": policy}}
	}
	payload, err := json.Marshal(map[string]interface{}{"RoleDetailList": []interface{}{role}})
	if err != nil {
		return models.Role{}, err
	}
	roles, err := detector.ParseIAM(payload)
	if err != nil {
		return models.Role{}, err
	}
	return roles[0], nil
}

func optionalString(after map[string]json.RawMessage, field string) (string, bool) {
	value, ok := after[field]
	if !ok {
		return "", false
	}
	var result string
	if json.Unmarshal(value, &result) != nil {
		return "", false
	}
	return result, true
}

func unmarshalString(object map[string]json.RawMessage, field string, target *string) error {
	value, ok := object[field]
	if !ok {
		return fmt.Errorf("missing %s", field)
	}
	return json.Unmarshal(value, target)
}

func isSupportedTerraformType(resourceType string) bool {
	switch resourceType {
	case "aws_iam_role", "aws_iam_role_policy", "aws_iam_policy", "aws_iam_role_policy_attachment", "aws_iam_policy_attachment":
		return true
	default:
		return false
	}
}

func isDeleteOnly(actions []string) bool {
	if len(actions) == 0 {
		return false
	}
	for _, action := range actions {
		if action != "delete" {
			return false
		}
	}
	return true
}

func isUnknown(unknown map[string]json.RawMessage, field string) bool {
	value, ok := unknown[field]
	if !ok {
		return false
	}
	var flag bool
	return json.Unmarshal(value, &flag) == nil && flag
}

func resolveRoleReference(reference string, roles map[string]int, addresses map[string]string) (string, bool) {
	if _, ok := roles[reference]; ok {
		return reference, true
	}
	if roleName, ok := addresses[reference]; ok {
		return roleName, true
	}
	roleName := detector.ExtractRoleNameFromARN(reference)
	_, ok := roles[roleName]
	return roleName, ok
}

func extractAccountFromARN(arn string) string {
	const prefix = "arn:aws:iam::"
	if len(arn) < len(prefix) || arn[:len(prefix)] != prefix {
		return ""
	}
	rest := arn[len(prefix):]
	for i, character := range rest {
		if character == ':' || character == '/' {
			return rest[:i]
		}
	}
	return rest
}

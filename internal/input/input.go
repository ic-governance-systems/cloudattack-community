package input

import (
	"encoding/json"
	"fmt"
	"strings"

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
	plan, err := ParseTerraformPlan(data)
	if err != nil {
		return nil, err
	}
	if len(plan.Uncertainties) > 0 {
		return nil, fmt.Errorf("Terraform IAM state is incomplete: %s (%s state, %s)", plan.Uncertainties[0].Address, plan.Uncertainties[0].Side, plan.Uncertainties[0].Reason)
	}
	return plan.AfterRoles, nil
}

// ParseTerraformPlan retains both Terraform comparison states and records
// resource-level uncertainty instead of treating incomplete values as absent.
func ParseTerraformPlan(data []byte) (models.TerraformPlan, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return models.TerraformPlan{}, fmt.Errorf("invalid Terraform plan JSON: %w", err)
	}

	formatVersion, ok := raw["format_version"]
	if !ok {
		return models.TerraformPlan{}, fmt.Errorf("unsupported Terraform input: missing format_version")
	}
	var version string
	if err := json.Unmarshal(formatVersion, &version); err != nil || version == "" {
		return models.TerraformPlan{}, fmt.Errorf("Terraform format_version must be a non-empty string")
	}
	resourceChangesRaw, ok := raw["resource_changes"]
	if !ok {
		return models.TerraformPlan{}, fmt.Errorf("unsupported Terraform input: missing resource_changes")
	}
	if string(resourceChangesRaw) == "null" {
		return models.TerraformPlan{}, fmt.Errorf("Terraform resource_changes must be an array")
	}
	var changes []json.RawMessage
	if err := json.Unmarshal(resourceChangesRaw, &changes); err != nil {
		return models.TerraformPlan{}, fmt.Errorf("Terraform resource_changes must be an array")
	}

	before := newTerraformStateBuilder("before")
	after := newTerraformStateBuilder("after")
	plan := models.TerraformPlan{}

	for i, changeRaw := range changes {
		change, err := decodeResourceChange(changeRaw, i)
		if err != nil {
			return models.TerraformPlan{}, err
		}
		if !isSupportedTerraformType(change.Type) {
			continue
		}
		if err := validateChange(change, i); err != nil {
			return models.TerraformPlan{}, err
		}
		beforePresent, afterPresent, err := statePresence(change.Actions)
		if err != nil {
			return models.TerraformPlan{}, fmt.Errorf("Terraform resource %q: %w", change.Address, err)
		}
		meta := models.TerraformResourceChange{
			Address: change.Address, PreviousAddress: change.PreviousAddress, Type: change.Type, Actions: change.Actions,
			BeforePresent: beforePresent, AfterPresent: afterPresent,
			BeforeKnown: !beforePresent, AfterKnown: !afterPresent,
		}
		if beforePresent {
			stateChange := change.forSide("before")
			meta.BeforeKnown, err = before.add(stateChange, i)
			if err != nil {
				return models.TerraformPlan{}, err
			}
		}
		if afterPresent {
			stateChange := change.forSide("after")
			meta.AfterKnown, err = after.add(stateChange, i)
			if err != nil {
				return models.TerraformPlan{}, err
			}
		}
		plan.Changes = append(plan.Changes, meta)
	}

	before.resolve()
	after.resolve()
	plan.BeforeRoles = before.roles
	plan.AfterRoles = after.roles
	plan.Uncertainties = append(plan.Uncertainties, before.uncertainties...)
	plan.Uncertainties = append(plan.Uncertainties, after.uncertainties...)
	for i := range plan.Changes {
		for _, uncertainty := range plan.Uncertainties {
			change := &plan.Changes[i]
			addressMatches := uncertainty.Address == change.Address || (uncertainty.Side == "before" && uncertainty.Address == change.PreviousAddress)
			if !addressMatches {
				continue
			}
			if uncertainty.Side == "before" {
				change.BeforeKnown = false
			} else {
				change.AfterKnown = false
			}
		}
	}
	return plan, nil
}

type terraformResourceChange struct {
	Address         string
	PreviousAddress string
	Type            string
	Actions         []string
	Before          map[string]json.RawMessage
	BeforeUnknown   map[string]json.RawMessage
	After           map[string]json.RawMessage
	AfterUnknown    map[string]json.RawMessage
}

func (change terraformResourceChange) forSide(side string) terraformResourceChange {
	if side == "before" {
		if change.PreviousAddress != "" {
			change.Address = change.PreviousAddress
		}
		change.After = change.Before
		change.AfterUnknown = change.BeforeUnknown
	}
	return change
}

func statePresence(actions []string) (before, after bool, err error) {
	if len(actions) == 1 {
		switch actions[0] {
		case "create":
			return false, true, nil
		case "delete":
			return true, false, nil
		case "update", "no-op":
			return true, true, nil
		}
	}
	if len(actions) == 2 && containsAction(actions, "create") && containsAction(actions, "delete") {
		return true, true, nil
	}
	return false, false, fmt.Errorf("unsupported actions %q", actions)
}

func containsAction(actions []string, wanted string) bool {
	for _, action := range actions {
		if action == wanted {
			return true
		}
	}
	return false
}

type terraformAttachment struct {
	address   string
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

type terraformStateBuilder struct {
	side          string
	roles         []models.Role
	roleByAddress map[string]int
	rolesByName   map[string][]int
	managed       map[string][]models.Policy
	attachments   []terraformAttachment
	uncertainties []models.TerraformUncertainty
}

func newTerraformStateBuilder(side string) *terraformStateBuilder {
	return &terraformStateBuilder{
		side:          side,
		roleByAddress: map[string]int{},
		rolesByName:   map[string][]int{},
		managed:       map[string][]models.Policy{},
	}
}

func (b *terraformStateBuilder) add(change terraformResourceChange, index int) (bool, error) {
	for _, field := range requiredStateFields(change.Type) {
		if isUnknown(change.AfterUnknown, field) {
			b.uncertainties = append(b.uncertainties, models.TerraformUncertainty{
				Address: change.Address, Side: b.side,
				Reason: fmt.Sprintf("required IAM field %q is unknown", field),
			})
			return false, nil
		}
		if _, exists := change.After[field]; !exists || string(change.After[field]) == "null" {
			b.uncertainties = append(b.uncertainties, models.TerraformUncertainty{
				Address: change.Address, Side: b.side,
				Reason: fmt.Sprintf("required IAM field %q is unavailable", field),
			})
			return false, nil
		}
	}

	switch change.Type {
	case "aws_iam_role":
		role, err := parseTerraformRole(change, index)
		if err != nil {
			return false, err
		}
		if role.AccountID == "" && trustNeedsRoleAccount(role.Trust) {
			b.uncertainties = append(b.uncertainties, models.TerraformUncertainty{
				Address: change.Address, Side: b.side,
				Reason: "role account ID is unavailable for interpreting an AWS trust principal",
			})
		}
		if _, exists := b.roleByAddress[role.Address]; exists {
			return false, fmt.Errorf("Terraform resource %q is duplicated", change.Address)
		}
		b.roleByAddress[role.Address] = len(b.roles)
		b.rolesByName[role.Name] = append(b.rolesByName[role.Name], len(b.roles))
		b.roles = append(b.roles, role)
	case "aws_iam_role_policy":
		role, policies, err := parseTerraformRolePolicy(change, index)
		if err != nil {
			return false, err
		}
		b.attachments = append(b.attachments, terraformAttachment{address: change.Address, role: role, policies: policies})
	case "aws_iam_policy":
		keys, policies, err := parseTerraformManagedPolicy(change, index)
		if err != nil {
			return false, err
		}
		if len(keys) == 0 {
			b.uncertainties = append(b.uncertainties, models.TerraformUncertainty{
				Address: change.Address, Side: b.side,
				Reason: "managed policy ARN or ID is unavailable for attachment resolution",
			})
			return false, nil
		}
		for _, key := range appendUnique(nil, keys...) {
			if _, exists := b.managed[key]; exists {
				b.managed[key] = nil
			} else {
				b.managed[key] = policies
			}
		}
	case "aws_iam_role_policy_attachment":
		attachment, err := parseTerraformRolePolicyAttachment(change, index)
		if err != nil {
			return false, err
		}
		b.attachments = append(b.attachments, attachment)
	case "aws_iam_policy_attachment":
		attachments, err := parseTerraformPolicyAttachment(change, index)
		if err != nil {
			return false, err
		}
		b.attachments = append(b.attachments, attachments...)
	}
	return true, nil
}

func (b *terraformStateBuilder) resolve() {
	for _, attachment := range b.attachments {
		policies := attachment.policies
		if attachment.policyARN != "" {
			var ok bool
			policies, ok = b.managed[attachment.policyARN]
			if !ok || policies == nil {
				reason := fmt.Sprintf("managed policy %q is not present in this Terraform state", attachment.policyARN)
				if ok {
					reason = fmt.Sprintf("managed policy reference %q is ambiguous in this Terraform state", attachment.policyARN)
				}
				b.uncertainties = append(b.uncertainties, models.TerraformUncertainty{
					Address: attachment.address, Side: b.side,
					Reason: reason,
				})
				continue
			}
		}
		for _, reference := range attachment.roles() {
			roleIndex, ok := b.resolveRole(reference)
			if !ok {
				b.uncertainties = append(b.uncertainties, models.TerraformUncertainty{
					Address: attachment.address, Side: b.side,
					Reason: fmt.Sprintf("role reference %q is not present or is ambiguous in this Terraform state", reference),
				})
				continue
			}
			for _, policy := range policies {
				policy.AttachmentAddresses = appendUnique(policy.AttachmentAddresses, attachment.address)
				b.appendPolicy(roleIndex, policy)
			}
		}
	}
}

func (b *terraformStateBuilder) resolveRole(reference string) (int, bool) {
	if index, ok := b.roleByAddress[reference]; ok {
		return index, true
	}
	roleName := reference
	if strings.HasPrefix(reference, "arn:") {
		roleName = detector.ExtractRoleNameFromARN(reference)
	}
	indexes := b.rolesByName[roleName]
	if len(indexes) != 1 {
		return 0, false
	}
	return indexes[0], true
}

func (b *terraformStateBuilder) appendPolicy(roleIndex int, policy models.Policy) {
	for i := range b.roles[roleIndex].Policies {
		existing := &b.roles[roleIndex].Policies[i]
		if existing.Address == policy.Address && existing.StatementIndex == policy.StatementIndex {
			existing.AttachmentAddresses = appendUnique(existing.AttachmentAddresses, policy.AttachmentAddresses...)
			return
		}
	}
	b.roles[roleIndex].Policies = append(b.roles[roleIndex].Policies, policy)
}

func requiredStateFields(resourceType string) []string {
	switch resourceType {
	case "aws_iam_role":
		return []string{"name", "assume_role_policy"}
	case "aws_iam_role_policy":
		return []string{"role", "policy"}
	case "aws_iam_policy":
		return []string{"policy"}
	case "aws_iam_role_policy_attachment":
		return []string{"role", "policy_arn"}
	case "aws_iam_policy_attachment":
		return []string{"roles", "policy_arn"}
	default:
		return nil
	}
}

func appendUnique(values []string, additions ...string) []string {
	for _, addition := range additions {
		found := false
		for _, value := range values {
			if value == addition {
				found = true
				break
			}
		}
		if !found && addition != "" {
			values = append(values, addition)
		}
	}
	return values
}

func trustNeedsRoleAccount(statements []models.Policy) bool {
	for _, statement := range statements {
		for _, principal := range statement.Principals {
			if principal.Type != "AWS" {
				continue
			}
			for _, value := range principal.Values {
				if _, ok := detectorAccount(value); ok {
					return true
				}
			}
		}
	}
	return false
}

func detectorAccount(principal string) (string, bool) {
	if validAWSAccountID(principal) {
		return principal, true
	}
	const prefix = "arn:aws:iam::"
	if !strings.HasPrefix(principal, prefix) {
		return "", false
	}
	rest := strings.TrimPrefix(principal, prefix)
	separator := strings.IndexAny(rest, ":/")
	if separator <= 0 {
		return "", false
	}
	account := rest[:separator]
	return account, validAWSAccountID(account)
}

func validAWSAccountID(value string) bool {
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

func decodeResourceChange(raw json.RawMessage, index int) (terraformResourceChange, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return terraformResourceChange{}, fmt.Errorf("Terraform resource_changes[%d] must be an object", index)
	}
	var change terraformResourceChange
	if err := unmarshalString(object, "address", &change.Address); err != nil {
		return terraformResourceChange{}, fmt.Errorf("Terraform resource_changes[%d] address must be a string", index)
	}
	if change.Address == "" {
		return terraformResourceChange{}, fmt.Errorf("Terraform resource_changes[%d] address must not be empty", index)
	}
	if previousRaw, ok := object["previous_address"]; ok && string(previousRaw) != "null" {
		if err := json.Unmarshal(previousRaw, &change.PreviousAddress); err != nil {
			return terraformResourceChange{}, fmt.Errorf("Terraform resource %q previous_address must be a string", change.Address)
		}
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
	if beforeRaw, ok := changeObject["before"]; ok && string(beforeRaw) != "null" {
		if err := json.Unmarshal(beforeRaw, &change.Before); err != nil {
			return terraformResourceChange{}, fmt.Errorf("Terraform resource %q change.before must be an object", change.Address)
		}
	}
	if beforeUnknownRaw, ok := changeObject["before_unknown"]; ok && string(beforeUnknownRaw) != "null" {
		if err := json.Unmarshal(beforeUnknownRaw, &change.BeforeUnknown); err != nil {
			return terraformResourceChange{}, fmt.Errorf("Terraform resource %q change.before_unknown must be an object", change.Address)
		}
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
	if _, _, err := statePresence(change.Actions); err != nil {
		return fmt.Errorf("Terraform resource %q %w", change.Address, err)
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
	parsed.Address = change.Address
	for i := range parsed.Trust {
		parsed.Trust[i].Address = change.Address
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
	for i := range parsed.Policies {
		parsed.Policies[i].Address = change.Address
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
	for i := range parsed.Policies {
		parsed.Policies[i].Address = change.Address
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
	return terraformAttachment{address: change.Address, role: role, policyARN: policyARN}, nil
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
	return []terraformAttachment{{address: change.Address, roleList: roleList, policyARN: policyARN}}, nil
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
	return containsUnknownValue(value)
}

func containsUnknownValue(value json.RawMessage) bool {
	var decoded interface{}
	if json.Unmarshal(value, &decoded) != nil {
		return false
	}
	switch typed := decoded.(type) {
	case bool:
		return typed
	case []interface{}:
		for _, item := range typed {
			encoded, _ := json.Marshal(item)
			if containsUnknownValue(encoded) {
				return true
			}
		}
	case map[string]interface{}:
		for _, item := range typed {
			encoded, _ := json.Marshal(item)
			if containsUnknownValue(encoded) {
				return true
			}
		}
	}
	return false
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

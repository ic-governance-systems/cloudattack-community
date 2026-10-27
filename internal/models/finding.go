package models

type ChangeClassification string

const (
	ChangeIntroduced ChangeClassification = "introduced"
	ChangeChanged    ChangeClassification = "changed"
	ChangeResolved   ChangeClassification = "resolved"
	ChangeUnchanged  ChangeClassification = "unchanged"
	ChangeUnknown    ChangeClassification = "unknown"
)

type Finding struct {
	RuleID                  string               `json:"rule_id,omitempty"`
	FindingID               string               `json:"finding_id,omitempty"`
	IdentityStatus          string               `json:"identity_status,omitempty"`
	Title                   string               `json:"title"`
	Severity                string               `json:"severity"`
	Role                    string               `json:"role"`
	Issue                   string               `json:"issue"`
	Impact                  string               `json:"impact"`
	Path                    []string             `json:"path,omitempty"`
	Limitations             []string             `json:"limitations,omitempty"`
	ResourceAddress         string               `json:"resource_address,omitempty"`
	PreviousResourceAddress string               `json:"previous_resource_address,omitempty"`
	RoleAddress             string               `json:"role_address,omitempty"`
	RelatedAddresses        []string             `json:"related_addresses,omitempty"`
	StatementIndex          *int                 `json:"statement_index,omitempty"`
	ChangeClassification    ChangeClassification `json:"change_classification,omitempty"`
	ChangeSummary           string               `json:"change_summary,omitempty"`
	Remediation             string               `json:"remediation,omitempty"`
	Evidence                FindingEvidence      `json:"evidence,omitempty"`
	MatchKey                string               `json:"-"`
	ContextFingerprint      string               `json:"-"`
	ChangeUncertain         bool                 `json:"-"`
	IdentityRole            string               `json:"-"`
	IdentitySubject         string               `json:"-"`
	IdentityPolicy          string               `json:"-"`
}

// FindingEvidence contains bounded IAM facts used to explain a detected
// pattern. It deliberately omits full policy documents and condition bodies.
type FindingEvidence struct {
	RoleReference       string   `json:"role_reference,omitempty"`
	PolicyReference     string   `json:"policy_reference,omitempty"`
	PrincipalReferences []string `json:"principal_references,omitempty"`
	ActionPatterns      []string `json:"action_patterns,omitempty"`
	ResourcePatterns    []string `json:"resource_patterns,omitempty"`
	ConditionPresent    bool     `json:"condition_present,omitempty"`
}

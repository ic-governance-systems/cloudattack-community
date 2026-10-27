package models

type Role struct {
	Name      string
	AccountID string
	Address   string
	Policies  []Policy
	Trust     []Policy
}

type Policy struct {
	Effect              string
	Actions             []string
	Resources           []string
	Principals          []Principal
	Condition           map[string]map[string]interface{}
	Address             string
	StatementIndex      int
	AttachmentAddresses []string
}

// Principal preserves the IAM principal category as well as its values. The
// category is security relevant: an AWS ARN, service principal and federated
// principal must not be treated as interchangeable strings.
type Principal struct {
	Type   string
	Values []string
}

package models

type Role struct {
	Name      string
	AccountID string
	Policies  []Policy
	Trust     []string
}

type Policy struct {
	Actions   []string
	Resources []string
}

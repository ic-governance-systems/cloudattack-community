package models

type TerraformPlan struct {
	BeforeRoles   []Role
	AfterRoles    []Role
	Changes       []TerraformResourceChange
	Uncertainties []TerraformUncertainty
}

type TerraformResourceChange struct {
	Address         string
	PreviousAddress string
	Type            string
	Actions         []string
	BeforeKnown     bool
	AfterKnown      bool
	BeforePresent   bool
	AfterPresent    bool
}

type TerraformUncertainty struct {
	Address string
	Side    string
	Reason  string
}

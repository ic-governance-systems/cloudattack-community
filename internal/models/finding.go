package models

type Finding struct {
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	Role     string   `json:"role"`
	Issue    string   `json:"issue"`
	Impact   string   `json:"impact"`
	Path     []string `json:"path,omitempty"`
}

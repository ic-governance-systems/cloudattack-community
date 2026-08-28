package models

type Report struct {
	Summary    string    `json:"summary"`
	Findings   []Finding `json:"findings"`
	SourceType string    `json:"-"`
}

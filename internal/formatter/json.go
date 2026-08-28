package formatter

import (
	"encoding/json"
	"strings"

	"cloudattack-community/internal/models"
	"cloudattack-community/internal/version"
)

// JSONReport is the versioned public machine-readable scan contract.
type JSONReport struct {
	SchemaVersion string        `json:"schema_version"`
	Tool          JSONTool      `json:"tool"`
	Scan          JSONScan      `json:"scan"`
	Summary       JSONSummary   `json:"summary"`
	Findings      []JSONFinding `json:"findings"`
}

type JSONTool struct {
	Name    string `json:"name"`
	Edition string `json:"edition"`
	Version string `json:"version"`
}

type JSONScan struct {
	SourceType string `json:"source_type"`
}

type JSONSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type JSONFinding struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Role     string   `json:"role"`
	Issue    string   `json:"issue"`
	Impact   string   `json:"impact"`
	Path     []string `json:"path"`
}

// ToJSON converts internal findings into the stable public JSON contract.
func ToJSON(report models.Report) (string, error) {
	sourceType := report.SourceType
	if sourceType == "" {
		sourceType = "aws-iam-json"
	}
	output := JSONReport{
		SchemaVersion: "1.0",
		Tool: JSONTool{
			Name:    "cloudattack",
			Edition: "community",
			Version: version.Current,
		},
		Scan:     JSONScan{SourceType: sourceType},
		Summary:  JSONSummary{},
		Findings: make([]JSONFinding, 0, len(report.Findings)),
	}

	for _, finding := range report.Findings {
		output.Summary.Total++
		switch strings.ToUpper(finding.Severity) {
		case "CRITICAL":
			output.Summary.Critical++
		case "HIGH":
			output.Summary.High++
		case "MEDIUM":
			output.Summary.Medium++
		case "LOW":
			output.Summary.Low++
		}

		path := finding.Path
		if path == nil {
			path = []string{}
		}
		output.Findings = append(output.Findings, JSONFinding{
			ID:       stableFindingID(finding.Title),
			Severity: finding.Severity,
			Title:    finding.Title,
			Role:     finding.Role,
			Issue:    finding.Issue,
			Impact:   finding.Impact,
			Path:     path,
		})
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func stableFindingID(title string) string {
	switch title {
	case "PassRole Risk Detected":
		return "passrole-risk"
	case "External Account Trust Relationship":
		return "external-account-trust"
	case "Overly Permissive Trust Policy":
		return "overly-permissive-trust"
	case "Privilege Escalation Path Detected":
		return "simple-privilege-escalation"
	case "Suspicious Trust Relationship":
		return "suspicious-trust-relationship"
	default:
		return slugify(title)
	}
}

func slugify(value string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(value) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if b.Len() > 0 {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

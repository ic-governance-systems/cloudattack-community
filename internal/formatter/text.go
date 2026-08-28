package formatter

import (
	"fmt"
	"strings"

	"cloudattack-community/internal/models"
)

func FromFindings(findings []models.Finding) models.Report {
	return FromFindingsWithSource(findings, "aws-iam-json")
}

// FromFindingsWithSource builds the internal report with its input source metadata.
func FromFindingsWithSource(findings []models.Finding, sourceType string) models.Report {
	return models.Report{
		Summary:    fmt.Sprintf("%d issues found", len(findings)),
		Findings:   findings,
		SourceType: sourceType,
	}
}

func ToText(report models.Report) string {
	var b strings.Builder

	b.WriteString("=== CloudAttack Community Edition ===\n\n")

	for _, f := range report.Findings {
		b.WriteString(fmt.Sprintf("[%s] %s\n\n", f.Severity, f.Title))
		b.WriteString("Role:\n")
		b.WriteString(fmt.Sprintf("  %s\n\n", f.Role))
		b.WriteString("Issue:\n")
		b.WriteString(fmt.Sprintf("  %s\n\n", f.Issue))
		b.WriteString("Impact:\n")
		b.WriteString(fmt.Sprintf("  %s\n\n", f.Impact))
		b.WriteString("Path:\n")
		b.WriteString(fmt.Sprintf("  %s\n\n", formatPath(f.Path)))
		b.WriteString("----------------------------------------\n\n")
	}

	b.WriteString("Summary:\n")
	b.WriteString(fmt.Sprintf("  %s\n", report.Summary))

	b.WriteString("\nNote:\n")
	b.WriteString("  This is the Community Edition (local analysis only).\n")
	b.WriteString("  Advanced attack-path simulation, multi-step privilege escalation analysis, and blast radius insights are available in the full platform.\n")

	return b.String()
}

// Render produces the requested report format. Additional formats can be
// added here without changing scan execution or report construction.
func Render(report models.Report, format string) (string, error) {
	switch strings.ToLower(format) {
	case "text":
		return ToText(report), nil
	case "json":
		return ToJSON(report)
	case "sarif":
		return ToSARIF(report)
	default:
		return "", fmt.Errorf("unsupported format %q (supported formats: text, json, sarif)", format)
	}
}

func formatPath(path []string) string {
	if len(path) == 0 {
		return "N/A"
	}

	var b strings.Builder
	for i, part := range path {
		if i > 0 {
			b.WriteString(" → ")
		}
		b.WriteString(part)
	}
	return b.String()
}

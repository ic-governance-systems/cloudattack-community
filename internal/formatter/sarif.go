package formatter

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"cloudattack-community/internal/models"
	"cloudattack-community/internal/version"
)

const sarifSchemaURI = "https://json.schemastore.org/sarif-2.1.0-rtm.5.json"

// SARIFReport is the public SARIF 2.1.0 output contract.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name"`
	ShortDescription     SARIFMessage           `json:"shortDescription"`
	DefaultConfiguration SARIFRuleConfiguration `json:"defaultConfiguration"`
}

type SARIFRuleConfiguration struct {
	Level string `json:"level"`
}

type SARIFResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    SARIFMessage    `json:"message"`
	Properties SARIFProperties `json:"properties"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFProperties struct {
	CloudAttackSeverity string   `json:"cloudattackSeverity"`
	CloudAttackPath     []string `json:"cloudattackPath,omitempty"`
}

// ToSARIF converts internal findings into a deterministic SARIF 2.1.0 report.
func ToSARIF(report models.Report) (string, error) {
	run := SARIFRun{
		Tool: SARIFTool{Driver: SARIFDriver{
			Name:           "CloudAttack",
			Version:        version.Current,
			InformationURI: "https://github.com/ic-governance-systems/cloudattack-community",
			Rules:          make([]SARIFRule, 0),
		}},
		Results: make([]SARIFResult, 0, len(report.Findings)),
	}

	rulesByID := make(map[string]SARIFRule)
	for _, finding := range report.Findings {
		ruleID := stableFindingID(finding.Title)
		if _, exists := rulesByID[ruleID]; !exists {
			rulesByID[ruleID] = SARIFRule{
				ID:               ruleID,
				Name:             finding.Title,
				ShortDescription: SARIFMessage{Text: finding.Title},
				DefaultConfiguration: SARIFRuleConfiguration{
					Level: sarifLevel(finding.Severity),
				},
			}
		}

		properties := SARIFProperties{CloudAttackSeverity: finding.Severity}
		if len(finding.Path) > 0 {
			properties.CloudAttackPath = append([]string{}, finding.Path...)
		}
		run.Results = append(run.Results, SARIFResult{
			RuleID: ruleID,
			Level:  sarifLevel(finding.Severity),
			Message: SARIFMessage{Text: fmt.Sprintf(
				"%s: %s Impact: %s Role: %s",
				finding.Title, finding.Issue, finding.Impact, finding.Role,
			)},
			Properties: properties,
		})
	}

	ruleIDs := make([]string, 0, len(rulesByID))
	for ruleID := range rulesByID {
		ruleIDs = append(ruleIDs, ruleID)
	}
	sort.Strings(ruleIDs)
	for _, ruleID := range ruleIDs {
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rulesByID[ruleID])
	}

	output := SARIFReport{
		Schema:  sarifSchemaURI,
		Version: "2.1.0",
		Runs:    []SARIFRun{run},
	}
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func sarifLevel(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW":
		return "note"
	default:
		return "warning"
	}
}

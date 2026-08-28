package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"cloudattack-community/internal/detector"
	"cloudattack-community/internal/formatter"
	"cloudattack-community/internal/input"
)

type scanOptions struct {
	inputFile     string
	terraformPlan string
	format        string
	failOn        string
}

var severityRanks = map[string]int{
	"LOW":      0,
	"MEDIUM":   1,
	"HIGH":     2,
	"CRITICAL": 3,
}

func runScan(args []string) int {
	options, err := parseScanOptions(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Invalid scan arguments:", err)
		return 2
	}

	inputPath := options.inputFile
	if inputPath == "" {
		inputPath = options.terraformPlan
	}
	data, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to read file:", err)
		return 2
	}
	if !json.Valid(data) {
		fmt.Fprintln(os.Stderr, "Failed to parse input: invalid JSON")
		return 2
	}

	roles, err := input.ParseSource(options.sourceType(), data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to parse input:", err)
		return 2
	}
	findings := detector.RunAnalysis(roles)

	report := formatter.FromFindingsWithSource(findings, options.sourceType())
	output, err := formatter.Render(report, options.format)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to format report:", err)
		return 2
	}
	fmt.Println(output)

	if options.failOn != "" {
		threshold := severityRanks[options.failOn]
		for _, finding := range findings {
			if severityRanks[strings.ToUpper(finding.Severity)] >= threshold {
				return 1
			}
		}
	}

	return 0
}

func parseScanOptions(args []string) (scanOptions, error) {
	options := scanOptions{format: "text"}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, value, hasValue := splitFlag(arg)
		switch name {
		case "--input", "--terraform-plan", "--format", "--fail-on":
			if !hasValue {
				if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
					return scanOptions{}, fmt.Errorf("%s requires a value", name)
				}
				i++
				value = args[i]
			}
			switch name {
			case "--input":
				options.inputFile = value
			case "--terraform-plan":
				options.terraformPlan = value
			case "--format":
				options.format = strings.ToLower(value)
			case "--fail-on":
				options.failOn = strings.ToUpper(value)
			}
		default:
			return scanOptions{}, fmt.Errorf("unknown argument %q", arg)
		}
	}

	if options.inputFile == "" && options.terraformPlan == "" {
		return scanOptions{}, fmt.Errorf("exactly one input source is required: --input or --terraform-plan")
	}
	if options.inputFile != "" && options.terraformPlan != "" {
		return scanOptions{}, fmt.Errorf("--input and --terraform-plan are mutually exclusive")
	}
	if options.format != "text" && options.format != "json" && options.format != "sarif" {
		return scanOptions{}, fmt.Errorf("unsupported format %q (supported formats: text, json, sarif)", options.format)
	}
	if options.failOn != "" {
		if _, ok := severityRanks[options.failOn]; !ok {
			return scanOptions{}, fmt.Errorf("unsupported --fail-on value %q (supported values: low, medium, high, critical)", options.failOn)
		}
	}

	return options, nil
}

func (options scanOptions) sourceType() string {
	if options.terraformPlan != "" {
		return input.SourceTerraformPlan
	}
	return input.SourceIAM
}

func splitFlag(arg string) (name, value string, hasValue bool) {
	parts := strings.SplitN(arg, "=", 2)
	name = parts[0]
	if len(parts) == 2 {
		return name, parts[1], true
	}
	return name, "", false
}

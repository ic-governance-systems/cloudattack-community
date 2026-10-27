package cli

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"cloudattack-community/internal/detector"
	"cloudattack-community/internal/formatter"
	"cloudattack-community/internal/input"
	"cloudattack-community/internal/models"
)

type scanOptions struct {
	inputFile     string
	terraformPlan string
	format        string
	failOn        string
	scanID        string
	repository    string
	commitSHA     string
	gitReference  string
	pullRequest   string
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

	var findings []models.Finding
	if options.terraformPlan != "" {
		plan, parseErr := input.ParseTerraformPlan(data)
		if parseErr != nil {
			fmt.Fprintln(os.Stderr, "Failed to parse input:", parseErr)
			return 2
		}
		findings = detector.RunTerraformAnalysis(plan)
		detector.AssignFindingIdentities(findings, plan)
	} else {
		roles, parseErr := input.ParseSource(options.sourceType(), data)
		if parseErr != nil {
			fmt.Fprintln(os.Stderr, "Failed to parse input:", parseErr)
			return 2
		}
		findings = detector.RunAnalysis(roles)
		detector.AssignFindingIdentities(findings, models.TerraformPlan{})
	}

	report := formatter.FromFindingsWithSource(findings, options.sourceType())
	provenance, err := buildScanProvenance(options, options.sourceType(), data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Invalid scan metadata:", err)
		return 2
	}
	report.Provenance = &provenance
	output, err := formatter.Render(report, options.format)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to format report:", err)
		return 2
	}
	fmt.Println(output)

	for _, finding := range findings {
		if finding.ChangeClassification == models.ChangeUnknown {
			return 1
		}
	}
	if options.failOn != "" {
		threshold := severityRanks[options.failOn]
		for _, finding := range findings {
			// Resolved risks stay visible in reports, but do not fail a gate.
			// All other classifications, including unknown, use their severity.
			if finding.ChangeClassification == models.ChangeResolved {
				continue
			}
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
		case "--input", "--terraform-plan", "--format", "--fail-on", "--scan-id", "--repository", "--commit-sha", "--git-ref", "--pull-request":
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
			case "--scan-id":
				options.scanID = value
			case "--repository":
				options.repository = value
			case "--commit-sha":
				options.commitSHA = value
			case "--git-ref":
				options.gitReference = value
			case "--pull-request":
				options.pullRequest = value
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
	if err := validateScanMetadata(options); err != nil {
		return scanOptions{}, err
	}

	return options, nil
}

var (
	scanIDPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	repositoryPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
	commitPattern       = regexp.MustCompile(`^[A-Fa-f0-9]{7,64}$`)
	gitReferencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/+@-]{0,255}$`)
	pullRequestPattern  = regexp.MustCompile(`^[1-9][0-9]{0,9}$`)
)

func validateScanMetadata(options scanOptions) error {
	if options.scanID != "" && !scanIDPattern.MatchString(options.scanID) {
		return fmt.Errorf("--scan-id must be 1-128 safe ASCII identifier characters")
	}
	if options.repository != "" && !repositoryPattern.MatchString(options.repository) {
		return fmt.Errorf("--repository must be a 1-256 character repository identifier without credentials or whitespace")
	}
	if options.commitSHA != "" && !commitPattern.MatchString(options.commitSHA) {
		return fmt.Errorf("--commit-sha must contain 7-64 hexadecimal characters")
	}
	if options.gitReference != "" && (!gitReferencePattern.MatchString(options.gitReference) || strings.Contains(options.gitReference, "..") || strings.Contains(options.gitReference, "//") || strings.Contains(options.gitReference, "@{") || strings.HasSuffix(options.gitReference, "/") || strings.HasSuffix(options.gitReference, ".") || strings.HasSuffix(options.gitReference, ".lock")) {
		return fmt.Errorf("--git-ref must be 1-256 printable ASCII characters")
	}
	if options.pullRequest != "" && !pullRequestPattern.MatchString(options.pullRequest) {
		return fmt.Errorf("--pull-request must be a positive decimal number of at most 10 digits")
	}
	return nil
}

func buildScanProvenance(options scanOptions, sourceType string, inputBytes []byte) (models.ScanProvenance, error) {
	scanID := options.scanID
	if scanID == "" {
		var err error
		scanID, err = newScanID()
		if err != nil {
			return models.ScanProvenance{}, fmt.Errorf("generate scan ID: %w", err)
		}
	}
	digest := sha256.Sum256(inputBytes)
	provenance := models.ScanProvenance{
		SchemaVersion: "1.0", ScanID: scanID, TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano),
		Scanner: models.ScannerProvenance{Name: "cloudattack", Edition: "community", Version: Version},
		Input:   models.InputProvenance{Type: sourceType, DigestAlgorithm: "sha256", ContentDigest: hex.EncodeToString(digest[:]), DigestScope: "raw-input-bytes"},
		Coverage: models.ScanCoverage{Scope: "supported-aws-iam-rules-and-terraform-resource-subset", Limitations: []string{
			"IAM conditions are preserved but not evaluated against runtime context.",
			"Findings describe potential configuration risks; effective permissions and exploitability are not calculated.",
			"Terraform before/after classification is limited to supported resources present in resource_changes.",
		}},
	}
	if options.repository != "" || options.commitSHA != "" || options.gitReference != "" || options.pullRequest != "" {
		provenance.Repository = &models.RepositoryProvenance{Identifier: options.repository, CommitSHA: strings.ToLower(options.commitSHA), GitReference: options.gitReference, PullRequest: options.pullRequest}
	}
	return provenance, nil
}

func newScanID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
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

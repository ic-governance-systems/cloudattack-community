package models

// ScanProvenance is caller-supplied or scanner-generated metadata for one
// execution. Repository fields are explicit optional values; they are never
// populated from the process environment.
type ScanProvenance struct {
	SchemaVersion string                `json:"schema_version"`
	ScanID        string                `json:"scan_id"`
	TimestampUTC  string                `json:"timestamp_utc"`
	Scanner       ScannerProvenance     `json:"scanner"`
	Input         InputProvenance       `json:"input"`
	Repository    *RepositoryProvenance `json:"repository,omitempty"`
	Coverage      ScanCoverage          `json:"coverage"`
}

type ScannerProvenance struct {
	Name    string `json:"name"`
	Edition string `json:"edition"`
	Version string `json:"version"`
}

type InputProvenance struct {
	Type            string `json:"type"`
	DigestAlgorithm string `json:"digest_algorithm"`
	ContentDigest   string `json:"content_digest"`
	DigestScope     string `json:"digest_scope"`
}

type RepositoryProvenance struct {
	Identifier   string `json:"identifier,omitempty"`
	CommitSHA    string `json:"commit_sha,omitempty"`
	GitReference string `json:"git_reference,omitempty"`
	PullRequest  string `json:"pull_request,omitempty"`
}

type ScanCoverage struct {
	Scope       string   `json:"scope"`
	Limitations []string `json:"limitations"`
}

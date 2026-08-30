# CloudAttack Community Edition

## Find dangerous AWS IAM changes before they reach production.

CloudAttack Community Edition is an open-source AWS IAM security tool for security, platform, and DevOps teams. It analyses AWS IAM configuration and Terraform plan JSON for risky trust relationships and privilege-escalation patterns. Run it locally or in GitHub Actions as a lightweight CI security gate.

```text
Terraform plan
      ↓
CloudAttack
      ↓
IAM security analysis
      ↓
PASS / FAIL
      ↓
JSON / SARIF / GitHub Actions
```

<!-- Future demo GIF or screenshot: insert here, below the flow and above Quick start. -->

CloudAttack analyses the files you provide. The current supported modes do not require AWS credentials, a CloudAttack account, or an IC Governance Systems service.

## Quick start

Build the CLI from this repository:

```bash
go build -o cloudattack ./cmd/cloudattack
```

### A. Scan existing AWS IAM JSON

```bash
cloudattack scan --input iam.json
```

The input is an AWS IAM JSON document containing supported role data. See [`examples/iam.json`](examples/iam.json).

### B. Scan a Terraform plan

Terraform must produce the plan JSON first; CloudAttack does not execute Terraform.

```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

cloudattack scan --terraform-plan tfplan.json
```

### C. Fail CI at a severity threshold

```bash
cloudattack scan \
  --terraform-plan tfplan.json \
  --fail-on high
```

Supported thresholds are `low`, `medium`, `high`, and `critical`. A finding at or above the selected threshold returns exit code `1`.

### D. Emit JSON or SARIF

```bash
cloudattack scan --terraform-plan tfplan.json --format json
cloudattack scan --terraform-plan tfplan.json --format sarif
```

The default CLI format is text. JSON is a structured report with scan metadata, severity counts, and findings. SARIF output is version 2.1.0.

## GitHub Actions

CloudAttack is a composite Action for Linux GitHub-hosted runners. The Terraform plan JSON must already exist before the Action runs.

```yaml
- name: Terraform plan
  run: |
    terraform plan -out=tfplan
    terraform show -json tfplan > tfplan.json

- name: CloudAttack
  uses: ic-governance-systems/cloudattack-community@v1
  with:
    terraform-plan: tfplan.json
    fail-on: high
```

The Action builds and invokes the CLI against the supplied Terraform plan. It does not execute Terraform or discover live AWS resources.

Action defaults and outputs:

- `fail-on` defaults to `high`.
- `format` defaults to `sarif`; supported values are `text`, `json`, and `sarif`.
- The report is written in the workspace as `cloudattack.sarif`, `cloudattack.json`, or `cloudattack.txt`.
- The `report-file` output identifies the selected report path.
- Exit code `0` means the scan completed without reaching the threshold; `1` means the threshold was reached; `2` means invocation, input, analysis, or configuration failed.

## SARIF and GitHub code scanning

CloudAttack can emit SARIF 2.1.0. Where GitHub code scanning is available, you can upload the report with GitHub’s own SARIF integration:

```yaml
- name: Upload CloudAttack SARIF
  if: ${{ always() }}
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: cloudattack.sarif
  continue-on-error: true
```

Use `if: ${{ always() }}` if the report should remain available when the CloudAttack threshold fails. Code-scanning availability, permissions, and retention depend on the repository and account settings; workflows commonly need `security-events: write`.

The optional upload sends SARIF findings to GitHub through GitHub’s mechanism. It does not send them to IC Governance Systems.

## What CloudAttack detects today

| Capability | Community Edition |
| --- | --- |
| AWS IAM JSON | Supported |
| Terraform plan JSON | Supported |
| `iam:PassRole` risk detection | Supported |
| External AWS account root trust detection | Supported |
| Trust for any principal | Supported |
| Suspicious trust relationships | Supported |
| Simple one-hop privilege-escalation chains | Supported |
| Human-readable text output | Supported |
| JSON output | Supported |
| SARIF 2.1.0 output | Supported |
| Severity gating | Supported |
| GitHub Actions | Supported |
| Local execution | Supported |
| AWS credentials required | No |
| CloudAttack account required | No |

The chain analysis is deliberately Community-bounded: it identifies a role that can pass another role which has trust relationships. It is not a deep or exhaustive attack graph.

## Example output

```text
=== CloudAttack Community Edition ===

[CRITICAL] PassRole Risk Detected

Role:
  developer-role

Issue:
  Role can pass iam:PassRole permission to admin-role

Impact:
  May enable privilege escalation into higher privilege role

Path:
  N/A

----------------------------------------

[HIGH] Overly Permissive Trust Policy

Role:
  developer-role

Issue:
  Trusts ANY principal

Impact:
  Any AWS identity may assume this role

Path:
  N/A

----------------------------------------

Summary:
  2 issues found
```

## Privacy and security model

- The CLI analyses input files locally.
- The GitHub Action runs inside the GitHub runner.
- Current supported modes do not require AWS credentials or a CloudAttack account.
- CloudAttack does not send scanned IAM or Terraform data to an IC Governance Systems service.
- If you configure SARIF upload, the findings are sent to GitHub through GitHub’s own integration and are subject to GitHub’s repository and account policies.

## Supported inputs

- AWS IAM JSON role data accepted by the IAM parser.
- Terraform plan JSON produced by `terraform show -json`.
- Terraform plan scanning currently handles IAM roles, inline role policies, managed IAM policies, role-policy attachments, and policy attachments.

Terraform plan JSON is required for Terraform scanning. CloudAttack does not parse raw HCL or run Terraform. If security-critical IAM fields are unsupported, malformed, unknown, or cannot be resolved, analysis can fail explicitly rather than silently passing.

## Current limitations

CloudAttack Community Edition is intentionally focused:

- AWS IAM only.
- Terraform plan JSON only; no raw HCL parsing.
- No Terraform execution.
- No live AWS discovery and no AWS credentials.
- No Azure or GCP support.
- No SaaS or cloud-telemetry analysis.
- No deep recursive or commercial attack-graph traversal.
- No blast-radius analysis.
- No remediation or remediation simulation.
- No sophisticated before/after pull-request risk diff.
- Unsupported or unresolvable security-critical Terraform IAM data may fail analysis instead of silently passing.

These boundaries describe the current Community implementation; they are not a claim of complete IAM security coverage.

## Community and advanced platform boundary

Community focuses on local AWS IAM and CI security analysis. A broader platform may provide capabilities such as richer attack-path analysis, remediation and risk intelligence, multi-account or multi-cloud workflows, and enterprise operations. This repository documents the Community boundary only.

## Releases and version pinning

For GitHub Actions, use:

- `@v1` for major-version-compatible usage.
- `@v1.0.0` for an immutable semantic release tag.
- A full commit SHA when security-sensitive workflows require immutable source pinning.

This repository currently has `v1` and `v1.0.0` tags. Release tags are maintained explicitly; release automation is not implied. CLI binaries should only be used when a maintainer has actually published them on the repository’s Releases page.

## Contributing

Changes should preserve the Community scope and include tests for behavior changes. Run:

```bash
go test ./...
git diff --check
```

## License

MIT License © IC Governance Systems Ltd

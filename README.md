```markdown
![Stylized badge indicating GitHub stars for the ic-governance-systems cloudattack-community repository](https://img.shields.io/github/stars/ic-governance-systems/cloudattack-community)

```

# CloudAttack Community Edition


### Identify AWS IAM privilege escalation paths before attackers do.

CloudAttack Community Edition is a local-only AWS IAM security analysis tool designed to identify privilege escalation risks, risky trust relationships, and identity misconfigurations directly from IAM JSON files.

---

## Why CloudAttack?

AWS IAM misconfigurations can unintentionally create privilege escalation paths and excessive access that attackers can exploit.

CloudAttack helps security teams, DevOps engineers, and cloud practitioners detect identity risks early—before they become security incidents.

---

## What it detects

* `iam:PassRole` abuse paths
* External account trust relationships
* Overly permissive trust policies
* Simple privilege escalation chains (maximum depth = 2)

---

## ⚡ Quick Start

```bash
cloudattack scan --input iam.json
```

To make a CI scan fail when a high-severity finding or above is detected:

```bash
cloudattack scan --input iam.json --fail-on high
```

For stable machine-readable output, request the versioned JSON report:

```bash
cloudattack scan --input iam.json --format json
```

The JSON report includes tool and scan metadata, severity counts, and structured findings.

For CI and security-tool integration, SARIF 2.1.0 output is also available:

```bash
cloudattack scan --input iam.json --format sarif
```

The SARIF report contains CloudAttack rules and results without fabricated source locations.

CloudAttack can also analyse Terraform plan JSON before deployment. Generate the JSON plan with Terraform, then scan it:

```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
cloudattack scan --terraform-plan tfplan.json
```

Terraform plan scans can use the existing machine-readable and CI-gating options:

```bash
cloudattack scan --terraform-plan tfplan.json --format json
cloudattack scan --terraform-plan tfplan.json --format sarif
cloudattack scan --terraform-plan tfplan.json --fail-on high
```

Phase B4 consumes Terraform plan JSON only; it does not parse raw HCL or run Terraform.

## GitHub Actions

CloudAttack provides a lightweight composite Action for Linux GitHub-hosted runners. It builds and invokes the existing CLI against Terraform plan JSON; it does not execute Terraform.

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

The Action defaults to `fail-on: high` and `format: sarif`. It writes the selected report to the workspace as `cloudattack.sarif`, `cloudattack.json`, or `cloudattack.txt`, and preserves the CloudAttack exit code: `0` succeeds, `1` indicates a threshold breach, and `2` indicates an invocation, input, analysis, or configuration error.

When GitHub code scanning is available for the repository, SARIF can be uploaded with GitHub's official integration:

```yaml
- name: CloudAttack
  uses: ic-governance-systems/cloudattack-community@v1
  with:
    terraform-plan: tfplan.json
    fail-on: high
    format: sarif

- name: Upload CloudAttack SARIF
  if: ${{ always() }}
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: cloudattack.sarif
  continue-on-error: true
```

The `always()` condition allows the SARIF report to remain available when the security threshold fails the Action. Code-scanning availability and required repository permissions vary; configure `security-events: write` where required. The Action runs locally in the GitHub runner, requires no AWS credentials, analyses the supplied Terraform plan JSON, and does not send the plan to an IC Governance Systems service. If you enable GitHub's SARIF/code-scanning upload, the SARIF findings are sent to GitHub through GitHub's own mechanism; GitHub's handling and availability are subject to its repository and account policies.

The repository's dogfood workflow validates a safe plan, a threshold failure, an analysis error, report artifacts, and the SARIF follow-up path. The threshold scenario intentionally records exit code `1`; the analysis-error scenario expects exit code `2` and no successful report. These scenarios require an actual GitHub-hosted Actions run to validate the runner and GitHub permissions.

Current limitations are AWS IAM-focused Terraform plan JSON only, no raw HCL parsing, no live AWS discovery, and no advanced pull-request before/after attack-path diffing. For releases, publish an immutable version tag and maintain a major `v1` tag as the stable Action reference; use a full immutable tag or commit when stricter pinning is required.

The recommended first Action release is `v1.0.0`, followed by a movable `v1` major tag. Release tags are not created automatically by this repository. After review and verification, a maintainer can publish them explicitly:

```bash
git tag -a v1.0.0 -m "CloudAttack Community Action v1.0.0"
git push origin v1.0.0
git tag -f v1 v1.0.0
git push origin v1 --force
```

Security-sensitive workflows should pin the full release tag or commit SHA instead of a movable major tag.

The scan uses the human-readable text format by default. The exit codes are:

* `0` — scan completed and no finding reached the configured `--fail-on` threshold (or no threshold was supplied)
* `1` — scan completed and at least one finding reached or exceeded the configured threshold
* `2` — invalid CLI arguments, invalid input, or another scan execution failure

## Example file

Use the provided example:
```
examples/iam.json
```
## Example output

```text
=== CloudAttack Community Edition ===

[CRITICAL] PassRole Risk Detected

Role:
  developer-role

Issue:
  Can pass role admin-role

Impact:
  May enable privilege escalation into higher privilege role

Path:
  N/A

----------------------------------------

[HIGH] Open Trust Policy

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

Note:
  This is the Community Edition (local analysis only).
  Advanced attack-path simulation, multi-step privilege escalation analysis,
  and blast radius insights are available in the full platform.
```

## Local Analysis Only

CloudAttack Community Edition performs analysis locally.

* No AWS credentials required
* No cloud connectivity required
* CloudAttack runs locally on your machine or in your GitHub runner
* CloudAttack does not send IAM or Terraform data to an IC Governance Systems service
* IAM JSON files are analysed directly from disk

## Who Is This For?

* AWS Security Engineers
* DevSecOps Engineers
* Platform Engineers
* Cloud Security Teams
* Security Consultants
* Internal Audit Teams

## Download

CloudAttack CLI release binaries may be available from the GitHub Releases page when published by maintainers. These are separate from the GitHub Action, which is used from repository release tags; neither CI nor the Action automatically publishes releases.

### Linux

```bash
tar -xzf cloudattack_linux_amd64.tar.gz
./cloudattack scan --input iam.json
```

### Windows

```powershell
cloudattack.exe scan --input iam.json
```

## Community Edition Scope

CloudAttack Community Edition focuses on local AWS IAM analysis and common identity risks.

Current capabilities include:

* IAM JSON analysis
* PassRole risk detection
* Trust relationship analysis
* Simple privilege escalation path detection
* Local execution with no cloud connectivity

## Future Platform

CloudAttack Community focuses on local AWS IAM analysis and Terraform plan inspection. Additional advanced capabilities may be reserved for a future full platform.

## Disclaimer

CloudAttack is intended for defensive security analysis and educational purposes only.

## License

MIT License © IC Governance Systems Ltd

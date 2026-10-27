# CloudAttack Community Edition

## Find dangerous AWS IAM changes before they reach production.

CloudAttack Community Edition is a source-available AWS IAM security tool distributed under the [CloudAttack Community License](LICENSE). It analyses AWS IAM configuration and Terraform plan JSON for risky trust relationships and privilege-escalation patterns. Run it locally or in GitHub Actions as a lightweight CI security gate.

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

The default CLI format is text. JSON is a structured report with scan provenance, severity counts, and findings. JSON schema version is `1.1`; SARIF output remains version 2.1.0.

Optional explicit provenance flags are `--scan-id`, `--repository`, `--commit-sha`, `--git-ref`, and `--pull-request`. For example:

```bash
cloudattack scan --terraform-plan tfplan.json --format json \
  --repository example/service --commit-sha 0123456789abcdef \
  --git-ref refs/pull/42/merge --pull-request 42
```

CloudAttack generates a UUID scan ID when `--scan-id` is omitted and records a UTC execution timestamp. Caller-supplied IDs are validated and bounded; callers should use unique values for distinct executions. Repository/commit/reference fields are omitted when not supplied. CloudAttack does not read repository metadata or credentials from environment variables. Provenance values supplied by a caller or GitHub Action are not cryptographically verified by CloudAttack.

The input content digest is SHA-256 over the exact raw bytes read from the input file, including whitespace and line endings; it is not a canonicalized JSON digest. JSON `id` remains the rule ID for compatibility. `rule_id` names the detection rule and `finding_id` identifies a stable occurrence when CloudAttack can establish one. Ambiguous occurrences have `identity_status: "ambiguous"` and omit `finding_id`. Finding IDs exclude scan ID and timestamp.

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
- Optional `scan-id`, `repository`, `commit-sha`, `git-ref`, and `pull-request` inputs pass explicit provenance values to the CLI. They default to empty and CloudAttack does not infer them from the runner environment.

For explicit provenance in a workflow, set these inputs from trusted workflow context, for example `repository: ${{ github.repository }}` and `commit-sha: ${{ github.sha }}`. Pull request number and ref can be passed the same way when available; CloudAttack does not select or read those context values on its own.
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
| Allow statements matching `iam:PassRole`, including IAM action wildcards | Supported |
| `iam:PassRole` resource scope for all roles or IAM role ARNs | Supported |
| External AWS account root trust detection (when the role account is known) | Supported |
| Explicit cross-account AWS role/account trust detection | Supported |
| Any-principal trust detection | Supported |
| Conditional PassRole review findings with an explicit unevaluated-condition caveat | Supported |
| One-hop PassRole/trust risk pattern | Supported; potential only |
| Human-readable text output | Supported |
| JSON output | Supported |
| SARIF 2.1.0 output | Supported |
| Severity gating | Supported |
| GitHub Actions | Supported |
| Local execution | Supported |
| AWS credentials required | No |
| CloudAttack account required | No |

## Terraform risk change classification

Terraform scans run the supported IAM rules against both `resource_changes.change.before` and `.after`, then retain the relevant resource address, role address, statement index, and attachment addresses on findings. This is a configuration-pattern comparison, not effective IAM evaluation.

| Classification | Meaning |
| --- | --- |
| `introduced` | The risk pattern is present after and all relevant before resources are explicitly known absent or risk-free. |
| `changed` | The same rule and Terraform statement context persists, with a material change to the analyzed IAM context. |
| `resolved` | A prior risk pattern is absent after and all relevant after resources are explicitly known. The finding remains in the report. |
| `unchanged` | The matched pattern and analyzed context are the same in both states. |
| `unknown` | A comparison resource/value is missing, unresolved, ambiguous, or conditions prevent a safe comparison. |

CloudAttack does not infer absence from a resource omitted from `resource_changes`. Unknown IAM values, unresolved role/policy attachments, missing before/after context and conditional findings produce high-severity `unknown` results and exit code `1`, including when no `--fail-on` threshold is supplied. Malformed plan or policy input still exits `2`.

With `--fail-on`, introduced, changed, unchanged and unknown findings use their severity; resolved findings are reported but do not fail the threshold gate. Unknown results fail closed independent of the selected severity threshold. Severity describes the risk pattern; classification describes how its plan state changed.

The comparison is limited to IAM roles, inline role policies, managed IAM policies, role-policy attachments and policy attachments represented in Terraform `resource_changes`. Managed policies that are referenced but not represented in the plan cannot be inspected and yield unknown context. Terraform does not provide source file/line attribution through this path, so none is inferred.

## Finding identity and evidence provenance

Each report has `provenance.schema_version: "1.0"`, a scan ID, UTC timestamp, scanner name/edition/version, input type and digest, coverage scope, and explicit limitations. Repository identifier, commit SHA, Git reference and pull request number are optional and appear only when explicitly supplied.

Finding `rule_id` and SARIF `ruleId` identify a rule. `finding_id` is a separate `caf1_` plus lowercase SHA-256 digest over canonical JSON containing the identity algorithm version, rule ID, role identity, Terraform resource identity (when available), and the risk subject. It does not hash full policy documents and does not include scan metadata. Terraform `previous_address` is used as the canonical resource identity only when the move mapping is unique. Statement indexes are evidence only; they do not determine finding IDs. If two findings share the same logical identity anchor or address mapping is ambiguous, IDs are omitted and the finding is marked ambiguous. Finding IDs are hashes, not encryption; role, resource and risk-subject values with low entropy may be guessable.

Identity stability is strongest for Terraform findings with stable resource addresses and distinct risk subjects. IAM JSON without resource addresses can produce ambiguous identities when equivalent occurrences cannot be distinguished. A later scan without a Terraform `previous_address` mapping may identify a moved resource by its new address because CloudAttack does not persist history between scans.

Structured finding evidence includes relevant role/policy references, matched action/resource patterns, principal references where applicable, statement index and whether a condition is present. Policy documents and full condition values are not copied into evidence. Resource addresses, role names, ARNs, principal references, finding issues, and the input digest may reveal infrastructure metadata. Protect reports accordingly; the input digest also enables equality checks against a known input. Provenance is trace metadata, not a signature or attestation.

JSON schema `1.1` adds optional provenance, finding identity, remediation and evidence fields. The legacy JSON `id` keeps its rule-ID meaning. SARIF remains 2.1.0 and carries the same CloudAttack-specific identity/evidence data in result and run properties. Consumers should use `rule_id`/SARIF `ruleId` for rule grouping and `finding_id` for occurrence correlation.

The one-hop analysis is deliberately Community-bounded. It reports a potential PassRole/trust relationship; it does not prove the caller can invoke a service, that the trust is usable in context, or that the target role grants greater privilege. It is not a deep or exhaustive attack graph.

## Example output

```text
=== CloudAttack Community Edition ===

[CRITICAL] PassRole Risk Detected

Role:
  developer-role

Issue:
  Role may pass iam:PassRole permission to admin-role

Impact:
  This permission pattern may let the role pass the target role to an AWS service; CloudAttack does not prove that it is exploitable.

Path:
  N/A

----------------------------------------

[HIGH] Overly Permissive Trust Policy

Role:
  developer-role

Issue:
  Trust statement allows any principal

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

## Supported IAM analysis subset

- Identity-policy statements must have `Effect` (`Allow` or `Deny`), `Action`, and `Resource`. Trust-policy statements must have `Effect`, `Action`, and `Principal`.
- `Deny` statements are preserved but do not create grant findings. Only `Allow` statements are considered for PassRole and trust findings.
- Action matching is case-insensitive and supports IAM `*` and `?` wildcards. A pattern is treated as a PassRole match only if it matches the complete `iam:PassRole` action name; arbitrary substring matches are not used.
- PassRole resources are limited to `*` or IAM role ARN patterns. Other service ARNs are ignored for this rule.
- Trust principals are retained by type. The current checks classify wildcard principals, external AWS account roots, and explicit external AWS account/role/user principals when the role's own AWS account is known. Explicit same-account AWS, Service, and Federated principals are not labelled suspicious by default. Other principal types are preserved but are not classified by the current rules.
- IAM `Condition` blocks are structurally validated and preserved, but are not evaluated. Conditional PassRole findings are emitted as high-severity review items so the default Action gate does not silently pass them, with a limitation explaining the uncertainty. Trust findings retain the same limitation when a condition is present.
- `NotAction`, `NotResource`, and `NotPrincipal` are unsupported and produce an analysis error (exit code `2`) instead of an inferred result. Malformed or incomplete statements, including missing effects, also produce an analysis error.
- These rules identify potential configuration risks. They do not calculate effective permissions, test runtime condition context, prove role assumption, or establish exploitability.

## P1 IAM behavior and output compatibility

P1 requires valid IAM statements to include `Effect`; older sample documents without it now fail analysis instead of being treated as grants. The generic `Suspicious Trust Relationship` classification has been narrowed: explicit external AWS role/account principals use a more specific finding, while same-account, Service, and Federated principals are not automatically flagged. One-hop findings are now titled `Potential PassRole Trust Relationship` so the title does not imply proven privilege escalation. Existing JSON and SARIF formats remain, with an optional `limitations` field added for findings whose conditions are not evaluated. Consumers that key on finding titles or IDs should account for the changed trust/chain classifications.

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
- No full effective-permission or exhaustive before/after IAM evaluation; change classification is limited to the supported rule/resource subset above.
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

## Licence

CloudAttack Community Edition is distributed under the [CloudAttack Community License, version 1.0](LICENSE). That licence grants royalty-free personal and internal organisational use, including internal CI/CD, plus evaluation, research and education, subject to its terms. It does not grant unrestricted commercial-use rights.

The licence restricts commercial redistribution, white-labelling, hosted or managed commercial services for third parties, incorporation of the Software or a substantial portion into competing commercial security products offered to third parties, and certain paid third-party client assessments. Separate written commercial permission is required for those activities. See the licence for the exact terms; this summary does not expand or replace it.

The licence permits internal use by a commercial organisation without a separate commercial licence when the use is for that organisation’s own internal purposes. A consultant or service provider may use CloudAttack for its own internal operations, but analysis directly for paying clients where CloudAttack is a material part of the deliverable or service requires separate written commercial permission. If a proposed use does not clearly fit these terms, seek owner/legal review before relying on it.

This custom licence is source-available and includes field-of-use restrictions; do not describe this release as OSI-defined open-source software. Versions previously released under MIT or another licence remain governed by their applicable earlier licence, as described in section 14 of `LICENSE`.

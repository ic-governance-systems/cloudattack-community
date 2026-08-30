# CloudAttack Terraform Demo

This demo shows CloudAttack scanning planned Terraform IAM state before deployment. It uses only checked-in, deterministic plan JSON fixtures; it does not need Terraform, AWS credentials, an AWS account, or deployment.

From the repository root, build the CLI once:

```bash
go build -o cloudattack ./cmd/cloudattack
```

On Windows, the binary is `cloudattack.exe`; substitute that name in the commands below.

## Scenario 1 - Safe IAM

[`safe/main.tf`](safe/main.tf) represents a Lambda execution role whose trust policy names the AWS Lambda service principal. The checked-in plan is [`plans/safe-plan.json`](plans/safe-plan.json).

```bash
cloudattack scan \
  --terraform-plan demo/plans/safe-plan.json \
  --fail-on high
```

Expected result: no findings reach the `high` threshold and the command exits with code `0`.

## Scenario 2 - PassRole Risk

[`vulnerable-passrole/main.tf`](vulnerable-passrole/main.tf) gives `developer-role` an inline policy allowing `iam:PassRole` on a role ARN in dummy account `000000000000`. A role that can pass another role is security-sensitive because it may enable privilege escalation into a higher-privilege role. CloudAttack detects the supported relationship; it does not claim to prove that an exploit will succeed.

```bash
cloudattack scan \
  --terraform-plan demo/plans/passrole-plan.json \
  --fail-on high
```

Expected result: a `[CRITICAL] PassRole Risk Detected` finding for `developer-role` and exit code `1`.

## Scenario 3 - Permissive Trust

[`vulnerable-trust/main.tf`](vulnerable-trust/main.tf) creates `publicly-trusted-role` with `Principal = "*"`. Broad trust can allow any AWS identity to assume the role, depending on the rest of the IAM configuration. CloudAttack reports this supported pattern as `Overly Permissive Trust Policy`.

```bash
cloudattack scan \
  --terraform-plan demo/plans/trust-plan.json \
  --fail-on high
```

Expected result: a `[HIGH] Overly Permissive Trust Policy` finding for `publicly-trusted-role` and exit code `1`.

## SARIF output

The same PassRole scan can produce SARIF 2.1.0 for CI tooling:

```bash
cloudattack scan \
  --terraform-plan demo/plans/passrole-plan.json \
  --format sarif \
  --fail-on high
```

The command still exits with code `1`; the finding is emitted in the report before the threshold exit. In GitHub Actions, the repository Action writes this output to `cloudattack.sarif`, which can optionally be uploaded through GitHub's SARIF integration.

## GitHub Actions context

The existing [CloudAttack dogfood workflow](../.github/workflows/cloudattack-fixture.yml) already demonstrates a safe plan, a threshold failure, SARIF artifact handling, and a distinct analysis error without duplicating infrastructure here. The fixtures in this directory are intended for the shorter local recording and can also be supplied to the same repository Action.

## Demo narrative

```text
Terraform change
      ->
CloudAttack scans planned IAM state
      ->
risky identity relationship detected
      ->
CI severity threshold reached
      ->
pipeline blocked before deployment
```

The demo is limited to the Community Edition's implemented AWS IAM and Terraform plan JSON behavior. It does not deploy resources or perform live AWS analysis.

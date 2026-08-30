# Demo recording script

Target duration: approximately 30-40 seconds. Record from the repository root with a terminal and editor visible. Use the existing local CLI or a GitHub Actions run; do not deploy Terraform.

## Scene 1 - Safe Terraform (5 seconds)

Open `demo/safe/main.tf`.

Say: "This is a minimal Lambda execution role. Its trust policy names the Lambda service principal."

## Scene 2 - Safe CI result (5 seconds)

Run:

```bash
cloudattack scan --terraform-plan demo/plans/safe-plan.json --fail-on high
```

Show the completed scan and exit code `0`.

Say: "The planned IAM state passes the high-severity gate."

## Scene 3 - PassRole change (7 seconds)

Open `demo/vulnerable-passrole/main.tf` and highlight only the `iam:PassRole` action and the dummy role ARN.

Say: "This developer role can pass another role. CloudAttack identifies that supported privilege-escalation pattern."

## Scene 4 - Failed security gate (8 seconds)

Run:

```bash
cloudattack scan --terraform-plan demo/plans/passrole-plan.json --fail-on high
```

Show:

```text
[CRITICAL] PassRole Risk Detected
Role:
  developer-role
```

Show exit code `1` and the failed security gate.

## Scene 5 - SARIF report (5 seconds)

Run:

```bash
cloudattack scan --terraform-plan demo/plans/passrole-plan.json --format sarif --fail-on high > cloudattack.sarif
```

Briefly show the SARIF `version` of `2.1.0` and the `passrole-risk` rule. The command intentionally exits `1` because the high threshold is reached.

## Scene 6 - Trust policy and landing page (7 seconds)

Optionally open `demo/vulnerable-trust/main.tf` and point to `Principal = "*"`, then show the README GitHub Actions snippet.

Say: "The same gate also detects an overly permissive trust policy. The README shows how to run the check in GitHub Actions before deployment."

## Accuracy notes

- The fixtures are checked-in Terraform plan JSON representations and use no credentials or real account IDs.
- CloudAttack analyses the planned IAM state; it does not execute Terraform, contact AWS, or prove exploitation.
- The trust scenario's expected result is `[HIGH] Overly Permissive Trust Policy`.
- The PassRole scenario's expected result is `[CRITICAL] PassRole Risk Detected`.

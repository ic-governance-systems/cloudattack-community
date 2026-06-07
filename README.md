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

## Usage

```bash
cloudattack scan --input examples/iam.json
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
* No data leaves your environment
* IAM JSON files are analysed directly from disk

## Who Is This For?

* AWS Security Engineers
* DevSecOps Engineers
* Platform Engineers
* Cloud Security Teams
* Security Consultants
* Internal Audit Teams

## Download

Download pre-built binaries from the Releases page.

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

CloudAttack is being developed as a broader cloud identity security platform.

Planned advanced capabilities include:

* Advanced attack-path simulation
* Multi-step privilege escalation analysis
* Risk scoring
* Blast radius analysis
* Account-wide visibility
* Enterprise reporting
* Continuous security monitoring

## Disclaimer

CloudAttack is intended for defensive security analysis and educational purposes only.

## License

MIT License © IC Governance Systems Ltd

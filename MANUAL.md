# 📙 `USER_MANUAL.md`

## AWS Security Hub as a Control Plane – User Manual

---

## 1. Purpose

This manual provides **operational guidance** for using the *AWS Security Hub as a Control Plane* framework.

It explains how to:

* Collect security findings as audit evidence
* Generate remediation plans from Security Hub findings
* Execute controlled remediations
* Validate remediation effectiveness
* Maintain traceability for governance and compliance

This manual is intended for **Cloud Security Engineers, DevSecOps, GRC teams, and auditors**.

---

## 2. Conceptual Overview

In this framework, **AWS Security Hub is treated as the authoritative control plane**, not merely a reporting dashboard.

Security operations follow a **closed-loop lifecycle**:

```
Detect → Plan → Remediate → Validate
```

Each phase produces **immutable, timestamped evidence**, suitable for audits and compliance assessments.

---

## 3. Prerequisites

### 3.1 Technical Requirements

* Python 3.9 or later
* AWS CLI configured with valid credentials
* Security Hub enabled in the target region

### 3.2 Required Python Packages

```bash
pip install boto3 pyyaml
```

### 3.3 Required IAM Permissions (Minimum)

The execution role or user must have permissions for:

* `securityhub:GetFindings`
* `securityhub:GetEnabledStandards`
* `securityhub:DescribeStandardsControls`
* `s3:*` (for S3 remediation)
* `ec2:*` (for Security Group and EBS remediation)

> ⚠️ It is strongly recommended to use a **dedicated remediation role** with scoped permissions.

---

## 4. Project Components

### 4.1 Scripts Overview

| Script                         | Description                                         |
| ------------------------------ | --------------------------------------------------- |
| `00_securityhub_scan.py`       | Collects Security Hub findings and control statuses |
| `01_securityhub_plan.py`       | Generates a remediation plan (read-only)            |
| `02_securityhub_remediate.py`  | Executes approved remediation actions               |
| `99_lab_insecure_resources.py` | Creates insecure resources for testing              |
| `remediate_map.yaml`           | Declarative remediation rule definitions            |

---

## 5. Scan Phase – Evidence Collection

### 5.1 Purpose

The scan phase extracts **Security Hub findings and control statuses** and stores them as **versioned evidence**.

No remediation occurs during this phase.

---

### 5.2 Execution

```bash
python scripts/00_securityhub_scan.py \
  --region us-east-1 \
  --severity HIGH,CRITICAL \
  --compliance FAILED
```

---

### 5.3 Outputs

Each execution creates a timestamped directory:

```
outputs/YYYYMMDDTHHMMSSZ/
```

Containing:

| File                   | Description                  |
| ---------------------- | ---------------------------- |
| `findings.jsonl`       | Canonical findings evidence  |
| `findings.csv`         | Human-readable findings      |
| `metadata.json`        | Scan context and filters     |
| `controls_status.json` | Standards and control states |

These files represent the **baseline security posture** at scan time.

---

## 6. Planning Phase – Remediation Plan Generation

### 6.1 Purpose

The planning phase translates findings into **proposed remediation actions**, without making any changes.

This step is **100% safe and read-only**.

---

### 6.2 Execution

```bash
python scripts/01_securityhub_plan.py \
  --findings outputs/<timestamp>/findings.jsonl \
  --rules config/remediate_map.yaml \
  --output outputs/<timestamp>/plan.json
```

---

### 6.3 Remediation Mapping Logic

Remediation rules are defined declaratively in `remediate_map.yaml`.

Each rule specifies:

* Matching keywords (`match_contains`)
* Action identifier (`action`)
* Optional parameters (`params`)
* Human-readable justification (`note`)

This design enables **policy-driven remediation** without modifying code.

---

### 6.4 Output

`plan.json` contains:

* All matched findings
* Proposed remediation actions
* Target resources
* Parameters required for execution

This file can be reviewed, approved, or archived.

---

## 7. Remediation Phase – Controlled Execution

### 7.1 Purpose

The remediation phase executes approved actions defined in the plan.

All remediations are **explicit and controlled**.

---

### 7.2 Dry-Run (Mandatory)

```bash
python scripts/02_securityhub_remediate.py \
  --region us-east-1 \
  --plan outputs/<timestamp>/plan.json \
  --dry-run
```

**Dry-run characteristics:**

* No AWS resources are modified
* All actions are logged
* Execution intent is fully visible

---

### 7.3 Apply Remediation

After validation and approval:

```bash
python scripts/02_securityhub_remediate.py \
  --region us-east-1 \
  --plan outputs/<timestamp>/plan.json
```

---

### 7.4 Outputs

Each remediation run generates a new evidence folder:

```
outputs/YYYYMMDDTHHMMSSZ/remediation_results.json
```

This file records:

* Each attempted action
* Target resources
* Execution result
* Errors or exceptions (if any)

---

## 8. Validation Phase – Post-Remediation Evidence

### 8.1 Purpose

Validation confirms that remediation actions effectively resolved the findings.

---

### 8.2 Execution

```bash
python scripts/00_securityhub_scan.py --region us-east-1
```

---

### 8.3 Validation Criteria

* Findings should transition to `RESOLVED`, `SUPPRESSED`, or no longer appear
* Control statuses should reflect compliance
* Evidence should demonstrate posture improvement

---

## 9. Operational Guidelines

* Always retain **pre- and post-remediation evidence**
* Use **version control** for remediation rules
* Review `plan.json` before execution
* Avoid running remediation scripts without dry-run
* Separate detection, approval, and execution roles when possible

---

## 10. Audit and Compliance Alignment

This framework supports:

* Evidence traceability
* Change justification
* Control validation
* Continuous compliance monitoring

It can be integrated with:

* AWS Audit Manager
* ISO 27001 / ISO 22301 frameworks
* CIS Benchmarks
* NIST CSF / SP 800-53

---

## 11. Limitations

* Not all findings can be auto-remediated
* Some services require manual intervention (e.g., RDS encryption)
* Multi-account support requires extension (roadmap item)

---

## 12. Conclusion

This manual describes a **governed, auditable, and extensible** approach to cloud security operations using AWS Security Hub as a control plane.

The framework enables teams to move from **visibility to action**, without sacrificing control or auditability.

---

# 📘 USER MANUAL

## AWS Security Hub as a Control Plane (Unified YAML Flow)

---

## 1. Purpose

This manual describes how to operate the **AWS Security Hub as a Control Plane** framework using a **single execution path** and a **single YAML control artifact**.

The framework enables teams to:

* Use AWS Security Hub as the **authoritative source of truth**
* Export findings into a **remediation-ready YAML**
* Decide and document remediation actions declaratively
* Execute remediations in **dry-run** or **apply** mode
* Preserve **audit-grade evidence** throughout the lifecycle

Target audience:
**Cloud Security Engineers, DevSecOps teams, Platform teams, and GRC/Audit professionals.**

---

## 2. Core Design Principles

* **Security Hub is the Control Plane**
* YAML is the **single source of truth**
* Detection, decision, and execution are **strictly separated**
* Automation is **governed**, not implicit
* Every step produces **immutable, versioned evidence**

There are **no alternative execution paths** and **no secondary output formats**.

---

## 3. Unified Lifecycle

The security lifecycle is strictly:

```
Detect → Export → Decide → Remediate → Validate
```

Mapped to scripts:

| Phase           | Script                        | Output |
| --------------- | ----------------------------- | ------ |
| Detect & Export | `00_securityhub_scan.py`      | YAML   |
| Decide          | `01_securityhub_plan.py`      | YAML   |
| Remediate       | `02_securityhub_remediate.py` | YAML   |
| Validate        | `00_securityhub_scan.py`      | YAML   |

---

## 4. Prerequisites

### 4.1 Technical Requirements

* Python **3.9+**
* AWS credentials configured (profile or environment variables)
* AWS Security Hub enabled in the target region

### 4.2 Python Dependencies

```bash
pip install boto3 pyyaml
```

### 4.3 IAM Permissions (Minimum)

**Evidence collection**

* `securityhub:GetFindings`
* `securityhub:GetEnabledStandards`
* `securityhub:DescribeStandardsControls`

**Remediation (depends on enabled controls)**

* S3: `s3:PutPublicAccessBlock`, `s3:PutBucketEncryption`, `s3:PutBucketVersioning`, `s3:PutBucketPolicy`
* EC2 / SG: `ec2:DescribeSecurityGroups`, `ec2:RevokeSecurityGroupIngress`
* EBS: `ec2:EnableEbsEncryptionByDefault`

> Recommended: use a **dedicated remediation role** with least privilege.

---

## 5. Project Components

### 5.1 Scripts

| Script                         | Responsibility                                              |
| ------------------------------ | ----------------------------------------------------------- |
| `00_securityhub_scan.py`       | Export Security Hub findings into a YAML control artifact   |
| `01_securityhub_plan.py`       | Apply remediation rules and promote items to AUTO or MANUAL |
| `02_securityhub_remediate.py`  | Execute remediations from the YAML artifact                 |
| `99_lab_insecure_resources.py` | Create insecure resources for testing                       |

### 5.2 Configuration

| File                        | Description                                           |
| --------------------------- | ----------------------------------------------------- |
| `config/remediate_map.yaml` | Declarative mapping of findings → remediation actions |

---

## 6. The YAML Control Artifact

All operations revolve around **one YAML file per execution**, stored under a timestamped directory:

```
outputs/YYYYMMDDTHHMMSSZ/securityhub_control_plane.yaml
```

This YAML contains:

* Normalized finding data
* Full raw Security Hub finding payload
* Decision metadata (`AUTO`, `MANUAL`, `IGNORE`)
* Remediation action and parameters
* Governance guardrails

### 6.1 YAML Structure (Simplified)

```yaml
apiVersion: shcp/v1
kind: SecurityHubControlPlane
metadata:
  generatedAt: "2026-01-08T18:00:00Z"
  region: "us-east-1"
spec:
  defaultMode: dry-run
  items:
    - id: item-000001
      finding:
        normalized: {...}
        raw: {...}
      decision:
        type: AUTO
        reason: "Matched rule: S3 bucket public exposure"
      action:
        name: s3_public_access_block
        params: {}
```

---

## 7. Step-by-Step Operation

---

### 7.1 Step 1 — Export Findings (Detection)

```bash
python scripts/00_securityhub_scan.py --region us-east-1
```

This step:

* Queries Security Hub
* Normalizes findings
* Preserves the **full raw payload**
* Produces the initial YAML artifact

All items are marked `MANUAL` by default.

---

### 7.2 Step 2 — Decide Remediation (Planning)

```bash
python scripts/01_securityhub_plan.py \
  --input-yaml outputs/<timestamp>/securityhub_control_plane.yaml \
  --rules config/remediate_map.yaml \
  --output-yaml outputs/<timestamp>/securityhub_control_plane.planned.yaml
```

This step:

* Applies `remediate_map.yaml`
* Promotes findings to `decision: AUTO` when matched
* Documents the **reason for each decision**
* Produces a **planned YAML** (still a single artifact type)

No AWS resources are modified.

---

### 7.3 Step 3 — Execute Remediation

#### Dry-run (mandatory)

```bash
python scripts/02_securityhub_remediate.py \
  --region us-east-1 \
  --yaml outputs/<timestamp>/securityhub_control_plane.planned.yaml \
  --mode dry-run
```

#### Apply (after approval)

```bash
python scripts/02_securityhub_remediate.py \
  --region us-east-1 \
  --yaml outputs/<timestamp>/securityhub_control_plane.planned.yaml \
  --mode apply
```

Only items with:

```yaml
decision:
  type: AUTO
```

are executed.

---

### 7.4 Best-Effort Remediation (Optional)

To remediate **as many safe controls as possible**, even when the decision is `MANUAL`:

```bash
python scripts/02_securityhub_remediate.py \
  --region us-east-1 \
  --yaml outputs/<timestamp>/securityhub_control_plane.planned.yaml \
  --mode dry-run \
  --best-effort
```

Best-effort mode:

* Uses keyword inference
* Executes only **safe baseline remediations**
* Must always be validated in dry-run first

---

### 7.5 Step 4 — Validate (Post-Remediation)

```bash
python scripts/00_securityhub_scan.py --region us-east-1
```

Validation confirms:

* Findings are resolved or no longer present
* Control status improved
* Evidence shows before/after posture

---

## 8. Supported Auto-Remediations (Release 1)

* S3 Public Access Block
* S3 Default Encryption (SSE-S3)
* S3 Versioning
* S3 HTTPS-only (SecureTransport)
* Security Group world-open port removal
* EBS Encryption by Default (regional)

---

## 9. Evidence and Audit Considerations

* Every step produces **timestamped YAML evidence**
* Decisions are explicit and reviewable
* Dry-run enforces safe change control
* The YAML artifact doubles as:

  * evidence
  * remediation plan
  * execution input

This design aligns naturally with:

* ISO 27001 / ISO 22301
* CIS Benchmarks
* NIST CSF / 800-53
* AWS Audit Manager workflows

---

## 10. Operational Guidelines

* Always retain **pre- and post-remediation YAML**
* Treat YAML as a **change-controlled artifact**
* Never run `--best-effort` directly in `apply`
* Start with S3 and SG controls before expanding scope
* Review remediation rules regularly

---

## 11. Limitations

* Not all findings are safe to auto-remediate
* IAM, KMS, and logging controls often require approval
* Multi-account execution requires extension (future work)

---

## 12. Conclusion

This framework turns AWS Security Hub into a **true Security Control Plane**.

It provides:

* Deterministic automation
* Explicit governance
* Audit-grade evidence
* Safe, extensible remediation

The result is **security as a controlled system**, not a reactive dashboard.


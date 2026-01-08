# AWS Security Hub as a Control Plane

This project transforms **AWS Security Hub** from a passive security dashboard into an **active, governed Security Control Plane**.

Instead of treating findings as informational alerts, this framework uses Security Hub as the **authoritative source of truth** to:

* Export findings into a **single YAML control artifact**
* Decide remediation actions declaratively
* Execute safe remediations (dry-run or apply)
* Preserve **audit-grade, versioned evidence**

The result is a **closed-loop security lifecycle** designed for real-world cloud governance.

---

## ✨ Key Features

* ✅ **Single execution path**
* ✅ **Single output format (YAML)**
* ✅ Security Hub as the **control plane**
* ✅ Declarative remediation rules (YAML-driven)
* ✅ Safe automation with mandatory dry-run
* ✅ Optional “best-effort” remediation mode
* ✅ Audit-ready evidence (pre- and post-remediation)

---

## 🎯 Why This Project Exists

Most organizations use Security Hub only for visibility.

This project answers a different question:

> **“How do we turn Security Hub findings into controlled, auditable action?”**

This framework provides that answer by separating:

* **Detection** (Security Hub)
* **Decision** (YAML rules and planning)
* **Execution** (explicit, governed remediation)
* **Validation** (re-scan and evidence)

---

## 🔁 Unified Security Lifecycle

```
Detect → Export → Decide → Remediate → Validate
```

Mapped directly to scripts:

| Phase           | Script                        | Output |
| --------------- | ----------------------------- | ------ |
| Detect & Export | `00_securityhub_scan.py`      | YAML   |
| Decide          | `01_securityhub_plan.py`      | YAML   |
| Remediate       | `02_securityhub_remediate.py` | YAML   |
| Validate        | `00_securityhub_scan.py`      | YAML   |

There are **no alternative paths** and **no secondary formats**.

---

## 📁 Project Structure

```
.
├── scripts/
│   ├── 00_securityhub_scan.py          # Export Security Hub findings to YAML
│   ├── 01_securityhub_plan.py          # Apply remediation rules (AUTO / MANUAL)
│   ├── 02_securityhub_remediate.py     # Execute remediations from YAML
│   └── 99_lab_insecure_resources.py    # Create insecure resources for testing
│
├── lib/
│   ├── aws_clients.py                  # AWS client/session helpers
│   ├── finding_matchers.py             # Keyword and pattern matching helpers
│   └── io_utils.py                     # IO, timestamps, utilities
│
├── config/
│   └── remediate_map.yaml              # Declarative remediation rules
│
├── outputs/
│   └── YYYYMMDDTHHMMSSZ/               # Versioned evidence folders
│
└── README.md
```

---

## 📄 The YAML Control Artifact

All operations revolve around **one YAML file per execution**, for example:

```
outputs/20260108T180000Z/securityhub_control_plane.yaml
```

This YAML acts simultaneously as:

* Evidence
* Remediation plan
* Execution input
* Audit artifact

### Simplified Structure

```yaml
apiVersion: shcp/v1
kind: SecurityHubControlPlane
metadata:
  generatedAt: "2026-01-08T18:00:00Z"
  region: "us-east-1"
spec:
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

## 🚀 Getting Started

### Prerequisites

* Python **3.9+**
* AWS credentials configured (CLI profile or environment variables)
* AWS Security Hub enabled in the target region

Install dependencies:

```bash
pip install boto3 pyyaml
```

---

## ▶️ Usage

### 1️⃣ Export Findings (Detection)

```bash
python scripts/00_securityhub_scan.py --region us-east-1
```

This generates the initial YAML artifact.
All items are marked as `MANUAL` by default.

---

### 2️⃣ Decide Remediation (Planning)

```bash
python scripts/01_securityhub_plan.py \
  --input-yaml outputs/<timestamp>/securityhub_control_plane.yaml \
  --rules config/remediate_map.yaml \
  --output-yaml outputs/<timestamp>/securityhub_control_plane.planned.yaml
```

This step:

* Applies declarative rules
* Promotes findings to `AUTO` or keeps them `MANUAL`
* Documents the decision reason
* Does **not** change any AWS resources

---

### 3️⃣ Execute Remediation

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

Only items marked as:

```yaml
decision:
  type: AUTO
```

are executed.

---

### 🔎 Optional: Best-Effort Remediation

To attempt remediation of **additional safe controls**, even when marked `MANUAL`:

```bash
python scripts/02_securityhub_remediate.py \
  --region us-east-1 \
  --yaml outputs/<timestamp>/securityhub_control_plane.planned.yaml \
  --mode dry-run \
  --best-effort
```

> ⚠️ Always validate best-effort mode using dry-run first.

---

### 4️⃣ Validate (Post-Remediation)

```bash
python scripts/00_securityhub_scan.py --region us-east-1
```

Use the new YAML output to validate posture improvement.

---

## 🔐 Supported Auto-Remediations (Release 1)

* S3 Public Access Block
* S3 Default Encryption (SSE-S3)
* S3 Versioning
* S3 HTTPS-only (SecureTransport)
* Security Group world-open port removal
* EBS Encryption by Default (regional)

---

## 🧪 Testing

The repository includes a lab script to create insecure resources:

```bash
python scripts/99_lab_insecure_resources.py --region us-east-1
```

This allows you to safely validate:

* Security Hub findings
* Rule matching
* Remediation execution
* Evidence lifecycle

---

## 📊 Governance & Audit Alignment

This project is designed to support:

* ISO 27001 / ISO 22301
* CIS Benchmarks
* NIST CSF / SP 800-53
* AWS Audit Manager evidence workflows

Key audit characteristics:

* Immutable evidence
* Explicit decision records
* Controlled execution
* Clear before/after posture

---

## ⚠️ Limitations

* Not all findings are safe for auto-remediation
* IAM, KMS, and logging controls often require manual approval
* Multi-account (AWS Organizations) support is a future enhancement

---

## 📜 License

MIT License

---

## 🤝 Contribution & Community

This project is intended as a **reference implementation** and learning tool.

Contributions, issues, and discussions are welcome — especially around:

* New safe remediation handlers
* Control mappings (CIS / ISO / NIST)
* Multi-account execution patterns


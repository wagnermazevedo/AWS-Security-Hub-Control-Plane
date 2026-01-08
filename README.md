# 📘 `README.md`

```markdown
# AWS Security Hub as a Control Plane

This project turns **AWS Security Hub** from a passive security dashboard into an **active Security Control Plane**.

Instead of using Security Hub only for visibility, this framework treats **Security Hub findings as authoritative inputs** that drive:

- Evidence collection (versioned and auditable)
- Remediation planning
- Automated corrective actions
- Post-remediation validation

The result is a **closed-loop security lifecycle** aligned with cloud governance and compliance needs.

---

## 🎯 Goals

- Use AWS Security Hub as the **single source of truth**
- Convert findings into **actionable remediation plans**
- Separate **detection**, **decision**, and **execution**
- Generate **audit-ready evidence**
- Enable safe automation with **dry-run first**
- Provide a foundation for ISO, CIS, and NIST controls

---

## 🔁 Security Lifecycle

```

Detect (Security Hub)
↓
Scan & Export Evidence
↓
Remediation Planning (YAML-driven)
↓
Execute Remediation (optional, controlled)
↓
Re-Scan & Validate

```

Security Hub remains the **control plane**, while remediation logic is externalized, transparent, and auditable.

---

## 🧱 Architecture Overview

```

AWS Security Hub
|
v
00_securityhub_scan.py
|
v
Versioned Outputs (JSONL / CSV)
|
v
01_securityhub_plan.py
|
v
Remediation Plan (plan.json)
|
v
02_securityhub_remediate.py
|
v
AWS APIs (S3, EC2, EBS)

```

---

## 📁 Project Structure

```

securityhub_control_plane/
├── scripts/
│   ├── 00_securityhub_scan.py          # Collect findings and controls evidence
│   ├── 01_securityhub_plan.py          # Generate remediation plan (no changes)
│   ├── 02_securityhub_remediate.py     # Execute remediation actions
│   ├── 99_lab_insecure_resources.py    # Create insecure resources for testing
│   └── lib/
│       ├── aws_clients.py              # AWS client/session helpers
│       ├── io_utils.py                 # Output, timestamps, helpers
│       └── finding_matchers.py         # Finding matching logic
├── config/
│   └── remediate_map.yaml              # Declarative remediation rules
├── outputs/                            # Versioned evidence outputs
└── README.md

````

---

## 🧠 Design Principles

- **Security Hub is authoritative** for detection
- **No direct remediation logic inside findings**
- **All decisions are declarative (YAML)**
- **Evidence is immutable and timestamped**
- **No automatic fixes without explicit execution**
- **Dry-run is mandatory before changes**

---

## ⚠️ Safety & Governance Controls

- Dry-run enabled by default
- Explicit execution required for remediation
- Resource-scoped actions only
- Full before/after evidence retained
- Easy integration with audit frameworks

---

## 🚀 Typical Usage Flow

### 1. Scan and collect evidence

```bash
python scripts/00_securityhub_scan.py --region us-east-1
````

Outputs are stored under:

```
outputs/YYYYMMDDTHHMMSSZ/
```

---

### 2. Generate remediation plan

```bash
python scripts/01_securityhub_plan.py \
  --findings outputs/<timestamp>/findings.jsonl \
  --rules config/remediate_map.yaml \
  --output outputs/<timestamp>/plan.json
```

This step is **read-only** and does not modify AWS resources.

---

### 3. Execute remediation (dry-run first)

```bash
python scripts/02_securityhub_remediate.py \
  --region us-east-1 \
  --plan outputs/<timestamp>/plan.json \
  --dry-run
```

---

### 4. Apply remediation

```bash
python scripts/02_securityhub_remediate.py \
  --region us-east-1 \
  --plan outputs/<timestamp>/plan.json
```

---

### 5. Re-scan for validation

```bash
python scripts/00_securityhub_scan.py --region us-east-1
```

---

## 🔧 Supported Remediations (v1)

* Enforce S3 Public Access Block
* Remove world-open SSH/RDP from Security Groups
* Enable EBS Encryption by Default

---

## 🧪 Testing Support

The project includes a lab script to intentionally create insecure resources:

```bash
python scripts/99_lab_insecure_resources.py --region us-east-1 --create-s3
```

This allows controlled validation of:

* Security Hub findings
* Remediation planning
* Corrective actions
* Evidence lifecycle

---

## 🔮 Roadmap

* Multi-account support (AWS Organizations)
* Audit Manager integration
* Control mapping (ISO 27001 / ISO 22301 / CIS / NIST)
* Exception and approval workflow
* Metrics (MTTR, drift, coverage)

---

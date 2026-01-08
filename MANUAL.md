Below is a **concise, audit-ready manual page** in **English**, describing **what the solution does**, **why**, **how to run it step by step**, and **what to expect from each output**.

You can use this **as-is** as:

* `MANUAL.md`
* `docs/USAGE.md`
* or the “How it works” section of your GitHub README

---

# ISO 22301 Evidence Automation with AWS Audit Manager

## Purpose

This project provides a **repeatable, versioned, and auditable way** to **emulate ISO 22301 (Business Continuity Management System)** requirements using **AWS-native services**, primarily:

* **AWS Audit Manager** (framework, assessment, reports)
* **AWS APIs** (CloudTrail, Config, Backup, Route53, CloudWatch, Security Hub, etc.)
* **S3** for evidence storage and versioning

The goal is **not to “certify” ISO 22301**, but to:

* Produce **technical and hybrid evidence** expected during an ISO 22301 audit
* Separate **automatable AWS evidence** from **external/manual evidence**
* Deliver **audit-ready artifacts** with traceability and repeatability

---

## High-Level Flow

```
1. Define ISO 22301-aligned controls (YAML)
2. Create a custom Audit Manager Framework
3. Create an Audit Manager Assessment
4. Collect evidence (AWS APIs + external placeholders)
5. Attach versioned evidence to controls
6. Generate an official Audit Manager report
```

Each step is **idempotent**, **scripted**, and **auditable**.

---

## Repository Structure

```
iso22301-auditmanager/
│
├── data/
│   └── iso22301_controls_full.yaml     # Control definitions (AWS + external)
│
├── scripts/
│   ├── 01_create_framework.py          # Create Audit Manager framework & controls
│   ├── 02_create_assessment.py         # Create assessment from framework
│   ├── 03_collect_evidence_pack.py     # Collect evidence (AWS + external placeholders)
│   ├── 04_attach_evidence_to_assessment.py
│   └── 05_generate_report.py           # Generate Audit Manager assessment report
│
└── outputs/
    └── evidence_pack_<region>_<ts>.json
```

---

## Step-by-Step Usage

### Prerequisites

* Python 3.9+
* AWS credentials with permissions for:

  * `auditmanager:*`
  * Read-only access to CloudTrail, Config, Backup, S3, Route53, CloudWatch, Security Hub, etc.
* An S3 bucket for evidence storage (recommended: versioning enabled)

Install dependencies:

```bash
pip install boto3 pyyaml
```

---

## Step 1 — Create the Audit Manager Framework

Creates:

* One **custom framework**
* One **control per ISO 22301-aligned requirement**
* Controls include **automated**, **hybrid**, and **external** evidence definitions

```bash
python scripts/01_create_framework.py \
  --region us-east-1 \
  --yaml data/iso22301_controls_full.yaml
```

### Expected Output

```json
{
  "framework_name": "ISO 22301 Emulation - AWS Evidence-20260108T180102Z",
  "framework_id": "f-1234567890",
  "framework_arn": "arn:aws:auditmanager:...",
  "controls_created": 12,
  "region": "us-east-1"
}
```

➡️ **Save the `framework_id`** — it is required in the next step.

---

## Step 2 — Create an Assessment

Creates an **Audit Manager assessment** based on the custom framework.

```bash
python scripts/02_create_assessment.py \
  --region us-east-1 \
  --framework-id <FRAMEWORK_ID>
```

### Expected Output

```json
{
  "assessment_name": "ISO22301-Assessment-20260108T180215Z",
  "assessment_id": "a-abcdef123456",
  "assessment_arn": "arn:aws:auditmanager:...",
  "framework_id": "f-1234567890"
}
```

➡️ **Save the `assessment_id`** — it is required for evidence attachment and reporting.

---

## Step 3 — Collect Evidence (Versioned Evidence Pack)

This step:

* Calls **AWS APIs** declared in the YAML
* Captures **real-time evidence snapshots**
* Lists **external evidence requirements** that must be supplied manually
* Generates a **versioned JSON evidence pack**

```bash
python scripts/03_collect_evidence_pack.py \
  --region us-east-1 \
  --yaml data/iso22301_controls_full.yaml \
  --outdir outputs \
  --s3-bucket <EVIDENCE_BUCKET> \
  --s3-prefix iso22301
```

### Expected Output (Local)

```
outputs/
└── evidence_pack_us-east-1_20260108T180401Z.json
```

### Evidence Pack Structure

```json
{
  "meta": {
    "timestamp_utc": "20260108T180401Z",
    "region": "us-east-1"
  },
  "aws_collected": {
    "BCP-LOG-01:cloudtrail:DescribeTrails": { ... },
    "BCP-BACKUP-01:backup:ListBackupPlans": { ... }
  },
  "external_required": {
    "BCP-EXT-DR-TEST-01": [
      "DR test report (PDF)",
      "RTO/RPO attestation"
    ]
  }
}
```

### Expected Output (S3)

```
s3://<bucket>/iso22301/us-east-1/packs/evidence_pack_<timestamp>.json
s3://<bucket>/iso22301/us-east-1/external/<timestamp>/<CONTROL-ID>/
```

---

## Step 4 — Attach Evidence to the Assessment

This step:

* Maps evidence to **Audit Manager controls**
* Attaches:

  * **AWS evidence** as structured text
  * **External evidence placeholders** (with optional S3 paths)
* Preserves **timestamped traceability**

```bash
python scripts/04_attach_evidence_to_assessment.py \
  --region us-east-1 \
  --assessment-id <ASSESSMENT_ID> \
  --evidence-pack outputs/evidence_pack_us-east-1_<TIMESTAMP>.json \
  --external-s3-bucket <EVIDENCE_BUCKET> \
  --external-s3-prefix iso22301/us-east-1/external
```

### Expected Output

```json
{
  "attached": [
    {
      "cid": "BCP-LOG-01",
      "controlId": "c-123",
      "items": 3,
      "errors": []
    }
  ],
  "missing_controls_in_assessment": []
}
```

➡️ At this point, the **Audit Manager console already shows populated evidence per control**.

---

## Step 5 — Generate the Audit Manager Report

Generates an **official assessment report**, suitable for auditors and GRC teams.

```bash
python scripts/05_generate_report.py \
  --region us-east-1 \
  --assessment-id <ASSESSMENT_ID> \
  --wait
```

### Expected Output

```json
{
  "report_id": "r-987654321",
  "status": "COMPLETE",
  "created_at": "2026-01-08T18:12:01Z",
  "s3_destination": {
    "destinationType": "S3"
  }
}
```

📄 The report will be available in the **S3 destination configured for Audit Manager reports**.

---

## What This Solution Delivers

✔ Repeatable ISO 22301-aligned evidence
✔ Clear separation of **AWS evidence vs external evidence**
✔ Versioned, timestamped audit trail
✔ Fully automated Audit Manager framework and reporting
✔ Auditor-friendly structure and outputs

---

## Important Notes for Auditors

* This framework **supports ISO 22301 audits** but does not replace:

  * Business Impact Analysis (BIA)
  * Policy approval
  * Management review
* External documents are **explicitly tracked** and referenced
* Evidence collection is **non-destructive** and read-only

---

## Typical Use Cases

* ISO 22301 readiness assessments
* Cloud BC/DR maturity reviews
* GRC automation demonstrations
* AWS Community Builder technical content
* Security & Resilience portfolio projects

---

**End of Manual**

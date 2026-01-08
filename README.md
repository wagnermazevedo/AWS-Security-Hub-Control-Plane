# Security Hub as Control Plane

## Overview

In many AWS environments, **Security Hub already aggregates security signals** —
but it is often treated as a passive dashboard.

This project turns AWS Security Hub into an **active control plane** for cloud security,
using findings as **decision signals** to drive automated, auditable remediation.

> If a finding already exists,  
> why not automate the response — with evidence?

This release builds on the *Foundation / Bootstrap* and introduces
**finding-driven security automation**.

---

## Objectives

- Use AWS Security Hub as a **single source of truth**
- Export findings and controls incrementally
- Generate **versioned, audit-ready evidence**
- Execute remediation actions mapped to finding types
- Ensure safety and control with **dry-run by default**

---

## Repository Structure

```text
.
├── scanner/
│   └── securityhub_scan.py
├── remediate/
│   └── securityhub_remediate.py
├── lab_insecure/
│   └── lab_insecure_securityhub.py
├── outputs/
│   └── YYYYMMDD-HHMMSS/
├── reports/
└── docs/

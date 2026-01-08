#!/usr/bin/env python3
import argparse, json, os
from datetime import datetime, timezone

import boto3
import yaml

def utc_ts():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

def load_yaml(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def main():
    ap = argparse.ArgumentParser(description="Create Audit Manager custom framework + controls (ISO 22301 emulation).")
    ap.add_argument("--region", default=os.getenv("AWS_REGION", "us-east-1"))
    ap.add_argument("--yaml", required=True, help="data/iso22301_controls_full.yaml")
    ap.add_argument("--framework-name", default=None)
    ap.add_argument("--framework-description", default=None)
    args = ap.parse_args()

    spec = load_yaml(args.yaml)
    framework_name = args.framework_name or f"{spec.get('name','ISO22301-Emulation')}-{utc_ts()}"
    framework_desc = args.framework_description or spec.get("description", "")

    audit = boto3.client("auditmanager", region_name=args.region)

    control_arns = []
    for c in spec["controls"]:
        control_name = f"{c['id']} - {c['title']}"
        evidence_summary = json.dumps(c.get("evidence", []), ensure_ascii=False)

        resp = audit.create_control(
            name=control_name,
            description=f"{c.get('iso_ref','')} | evidence_spec={evidence_summary}",
            testingInformation=(
                "Automated evidence is collected by scripts and imported to assessment. "
                "External evidence must be uploaded and linked/attached."
            ),
            actionPlanTitle="Remediate / Collect missing evidence",
            actionPlanInstructions=(
                "Run scripts/03_collect_evidence_pack.py then scripts/04_attach_evidence_to_assessment.py. "
                "For external evidence, upload artifacts to the defined S3 folder and re-attach links."
            ),
            controlMappingSources=[]
        )
        control_arns.append(resp["control"]["arn"])

    # one control set for simplicity
    framework_resp = audit.create_assessment_framework(
        name=framework_name,
        description=framework_desc,
        complianceType="ISO 22301 (Emulation)",
        controlSets=[{
            "name": "BCMS Technical & Hybrid Controls",
            "controls": [{"id": arn} for arn in control_arns]
        }]
    )

    out = {
        "region": args.region,
        "framework_name": framework_name,
        "framework_id": framework_resp["framework"]["id"],
        "framework_arn": framework_resp["framework"]["arn"],
        "controls_created": len(control_arns),
    }
    print(json.dumps(out, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()

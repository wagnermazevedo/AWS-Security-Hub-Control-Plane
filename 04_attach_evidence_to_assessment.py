#!/usr/bin/env python3
import argparse, json, os
from datetime import datetime, timezone

import boto3

def utc_ts():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def list_all_controls(audit, assessment_id):
    # Controls are grouped by control sets in Audit Manager.
    assessment = audit.get_assessment(assessmentId=assessment_id)["assessment"]
    framework_id = assessment["frameworkId"]

    # For each control set, list controls
    controls = []
    next_token = None
    while True:
        kwargs = {"assessmentId": assessment_id}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = audit.list_assessment_control_sets(**kwargs)
        for cs in resp.get("controlSets", []):
            cs_id = cs["id"]
            # list controls in control set
            c_next = None
            while True:
                c_kwargs = {"assessmentId": assessment_id, "controlSetId": cs_id}
                if c_next:
                    c_kwargs["nextToken"] = c_next
                c_resp = audit.list_assessment_controls(**c_kwargs)
                controls.extend([{
                    "controlSetId": cs_id,
                    "id": c["id"],
                    "name": c["name"],  # contains "BCP-XXX - title"
                } for c in c_resp.get("controls", [])])
                c_next = c_resp.get("nextToken")
                if not c_next:
                    break
        next_token = resp.get("nextToken")
        if not next_token:
            break

    return controls

def normalize_control_id(control_name):
    # "BCP-LOG-01 - CloudTrail enabled..." -> "BCP-LOG-01"
    return control_name.split(" - ")[0].strip()

def import_evidence(audit, assessment_id, control_set_id, control_id, evidence_items):
    # BatchImportEvidenceToAssessmentControl expects list of "manualEvidence"
    # We'll use "manualEvidence" with content in "evidenceFileName" + "textResponse" + optional "s3ResourcePath"
    resp = audit.batch_import_evidence_to_assessment_control(
        assessmentId=assessment_id,
        controlSetId=control_set_id,
        controlId=control_id,
        manualEvidence=evidence_items
    )
    return resp

def main():
    ap = argparse.ArgumentParser(description="Attach evidence pack to Audit Manager assessment controls (versioned).")
    ap.add_argument("--region", default=os.getenv("AWS_REGION", "us-east-1"))
    ap.add_argument("--assessment-id", required=True)
    ap.add_argument("--evidence-pack", required=True)
    ap.add_argument("--external-s3-bucket", default=None)
    ap.add_argument("--external-s3-prefix", default=None, help="Prefix base where external artifacts were uploaded (ts folder).")
    ap.add_argument("--max-items-per-call", type=int, default=25)
    args = ap.parse_args()

    audit = boto3.client("auditmanager", region_name=args.region)
    pack = load_json(args.evidence_pack)
    ts = pack["meta"]["timestamp_utc"]

    controls = list_all_controls(audit, args.assessment_id)

    # index by BCP id
    by_cid = {}
    for c in controls:
        cid = normalize_control_id(c["name"])
        by_cid.setdefault(cid, []).append(c)

    attach_report = {
        "meta": {"timestamp_utc": utc_ts(), "evidence_pack_ts": ts, "region": args.region},
        "attached": [],
        "missing_controls_in_assessment": [],
    }

    # 1) Attach AWS collected evidence
    # Keys are like "BCP-LOG-01:cloudtrail:DescribeTrails"
    aws_collected = pack.get("aws_collected", {})
    per_control_payload = {}
    for k, v in aws_collected.items():
        cid = k.split(":")[0]
        per_control_payload.setdefault(cid, []).append((k, v))

    for cid, items in per_control_payload.items():
        if cid not in by_cid:
            attach_report["missing_controls_in_assessment"].append(cid)
            continue

        for target in by_cid[cid]:
            evidence_items = []
            for (key, val) in items:
                snippet = json.dumps(val, ensure_ascii=False)[:6000]  # keep bounded
                evidence_items.append({
                    "evidenceFileName": f"{cid}_{key.replace(':','_')}_{ts}.json",
                    "textResponse": snippet,
                })

            # chunk calls
            for i in range(0, len(evidence_items), args.max_items_per_call):
                chunk = evidence_items[i:i+args.max_items_per_call]
                resp = import_evidence(audit, args.assessment_id, target["controlSetId"], target["id"], chunk)
                attach_report["attached"].append({
                    "cid": cid,
                    "controlSetId": target["controlSetId"],
                    "controlId": target["id"],
                    "items": len(chunk),
                    "errors": resp.get("errors", [])
                })

    # 2) Attach EXTERNAL placeholders
    external_required = pack.get("external_required", {})
    for cid, reqs in external_required.items():
        if cid not in by_cid:
            attach_report["missing_controls_in_assessment"].append(cid)
            continue

        for target in by_cid[cid]:
            evidence_items = []
            for r in reqs:
                item = {
                    "evidenceFileName": f"{cid}_EXTERNAL_{ts}.txt",
                    "textResponse": f"EXTERNAL EVIDENCE REQUIRED: {r}"
                }
                # optionally point to S3 folder convention
                if args.external_s3_bucket and args.external_s3_prefix:
                    # expected: s3://bucket/prefix/<ts>/<cid>/...
                    item["s3ResourcePath"] = f"s3://{args.external_s3_bucket}/{args.external_s3_prefix}/{ts}/{cid}/"
                evidence_items.append(item)

            resp = import_evidence(audit, args.assessment_id, target["controlSetId"], target["id"], evidence_items)
            attach_report["attached"].append({
                "cid": cid,
                "controlSetId": target["controlSetId"],
                "controlId": target["id"],
                "items": len(evidence_items),
                "errors": resp.get("errors", [])
            })

    print(json.dumps(attach_report, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()

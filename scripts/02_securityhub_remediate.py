import argparse
import os
from typing import Any, Dict, Tuple

import yaml

from lib.aws_clients import get_client
from lib.io_utils import ensure_directory, utc_timestamp


def remediate_s3_public_access_block(s3, bucket: str, dry_run: bool) -> Tuple[bool, str]:
    if dry_run:
        return True, f"DRY-RUN: would enable S3 Public Access Block on bucket {bucket}"
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    return True, f"OK: enabled S3 Public Access Block on bucket {bucket}"


def extract_bucket_from_arn(arn: str) -> str:
    # arn:aws:s3:::bucket-name
    return arn.split(":::")[-1]


def main():
    ap = argparse.ArgumentParser(description="Execute remediations from a universal YAML export/plan")
    ap.add_argument("--region", required=True)
    ap.add_argument("--yaml", required=True, help="Path to securityhub_findings_export.yaml or actions.yaml")
    ap.add_argument("--mode", choices=["dry-run", "apply"], default="dry-run")
    ap.add_argument("--output-dir", default="outputs")
    args = ap.parse_args()

    dry_run = args.mode == "dry-run"

    with open(args.yaml, "r", encoding="utf-8") as f:
        doc = yaml.safe_load(f)

    s3 = get_client("s3", region=args.region)
    ec2 = get_client("ec2", region=args.region)

    results = {
        "apiVersion": "shcp/v1",
        "kind": "RemediationResults",
        "metadata": {
            "executedAt": utc_timestamp(),
            "region": args.region,
            "mode": args.mode,
            "sourceYaml": args.yaml,
        },
        "spec": {
            "results": []
        }
    }

    for item in doc.get("spec", {}).get("items", []):
        action = item.get("action", {}) or {}
        action_name = action.get("name", "manual")
        decision = item.get("decision", {}) or {}
        decision_type = decision.get("type", "MANUAL")

        finding_norm = (item.get("finding", {}) or {}).get("normalized", {}) or {}
        resources = finding_norm.get("resources", []) or []

        ok, msg = False, "MANUAL_REQUIRED"

        # Only execute if decision is AUTO and action is supported
        if decision_type == "AUTO" and action_name != "manual":
            try:
                if action_name == "s3_public_access_block":
                    # Find an S3 resource
                    bucket = None
                    for r in resources:
                        if (r.get("type") or "").lower() in ["awss3bucket", "s3_bucket"]:
                            rid = r.get("id")
                            if rid and "arn:aws:s3:::" in rid:
                                bucket = extract_bucket_from_arn(rid)
                                break
                    if not bucket:
                        ok, msg = False, "Could not determine bucket target from finding resources"
                    else:
                        ok, msg = remediate_s3_public_access_block(s3, bucket, dry_run)
                else:
                    ok, msg = False, f"UNSUPPORTED_ACTION: {action_name}"
            except Exception as e:
                ok, msg = False, f"ERROR: {type(e).__name__}: {e}"
        else:
            # Always produce a result record even when manual/ignored
            ok = False
            if decision_type == "IGNORE":
                msg = "IGNORED"
            elif decision_type == "MANUAL":
                msg = "MANUAL_REQUIRED"
            else:
                msg = f"NOT_EXECUTED (decision={decision_type}, action={action_name})"

        results["spec"]["results"].append({
            "itemId": item.get("id"),
            "findingId": finding_norm.get("findingId"),
            "title": finding_norm.get("title"),
            "decision": decision_type,
            "action": action_name,
            "ok": ok,
            "message": msg,
        })

    ts = results["metadata"]["executedAt"]
    out_dir = os.path.join(args.output_dir, ts)
    ensure_directory(out_dir)

    out_path = os.path.join(out_dir, "remediation_results.yaml")
    with open(out_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(results, f, sort_keys=False, allow_unicode=True)

    print(f"[OK] Results written: {out_path}")
    print(f" - items: {len(results['spec']['results'])}")


if __name__ == "__main__":
    main()

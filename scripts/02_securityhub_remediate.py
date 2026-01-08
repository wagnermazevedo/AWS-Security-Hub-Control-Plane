import argparse
import os
from typing import Any, Dict, List, Optional, Tuple

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


def extract_bucket_from_arn_or_id(resource_id: str) -> Optional[str]:
    """
    Accepts:
    - arn:aws:s3:::bucket-name
    - bucket-name
    Returns bucket-name or None.
    """
    if not resource_id:
        return None
    if "arn:aws:s3:::" in resource_id:
        return resource_id.split(":::")[-1].strip()
    # fallback: if it looks like a bucket name, accept it
    if resource_id.startswith("s3://"):
        return resource_id.replace("s3://", "").strip().strip("/")
    if "://" not in resource_id and "/" not in resource_id and ":" not in resource_id:
        return resource_id.strip()
    return None


def find_s3_bucket_target(resources: List[Dict[str, Any]]) -> Optional[str]:
    """
    Try to find an S3 bucket from normalized resources.
    Works with types like:
    - AwsS3Bucket
    - awss3bucket
    - s3_bucket
    And IDs like:
    - arn:aws:s3:::my-bucket
    - my-bucket
    """
    for r in resources:
        r_type = (r.get("type") or "").lower()
        r_id = r.get("id") or ""
        if "s3" in r_type and "bucket" in r_type:
            bucket = extract_bucket_from_arn_or_id(r_id)
            if bucket:
                return bucket
    # fallback: attempt extraction from any resource id
    for r in resources:
        bucket = extract_bucket_from_arn_or_id(r.get("id") or "")
        if bucket:
            return bucket
    return None


def main():
    ap = argparse.ArgumentParser(
        description="Security Hub Control Plane - Execute remediations from a single YAML control artifact"
    )
    ap.add_argument("--region", required=True)
    ap.add_argument("--profile", default=None)
    ap.add_argument(
        "--yaml",
        required=True,
        help="Path to the YAML control artifact (e.g., outputs/<ts>/securityhub_control_plane.yaml)",
    )
    ap.add_argument("--mode", choices=["dry-run", "apply"], default="dry-run")
    ap.add_argument("--output-dir", default="outputs")
    args = ap.parse_args()

    dry_run = args.mode == "dry-run"

    with open(args.yaml, "r", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}

    s3 = get_client("s3", region=args.region, profile=args.profile)

    executed_at = utc_timestamp()
    results = {
        "apiVersion": "shcp/v1",
        "kind": "RemediationResults",
        "metadata": {
            "executedAt": executed_at,
            "region": args.region,
            "mode": args.mode,
            "sourceYaml": args.yaml,
        },
        "spec": {
            "results": [],
            "summary": {
                "total": 0,
                "executed": 0,
                "succeeded": 0,
                "failed": 0,
                "manual_required": 0,
                "ignored": 0,
                "unsupported": 0,
                "not_executed": 0,
            },
        },
    }

    items = (doc.get("spec", {}) or {}).get("items", []) or []
    results["spec"]["summary"]["total"] = len(items)

    for item in items:
        action = (item.get("action") or {})
        action_name = action.get("name", "manual")

        decision = (item.get("decision") or {})
        decision_type = decision.get("type", "MANUAL")

        finding_norm = ((item.get("finding") or {}).get("normalized") or {})
        resources = finding_norm.get("resources", []) or []

        ok = False
        msg = "MANUAL_REQUIRED"

        # Execute only if decision == AUTO and action != manual
        if decision_type == "AUTO" and action_name != "manual":
            results["spec"]["summary"]["executed"] += 1
            try:
                if action_name == "s3_public_access_block":
                    bucket = find_s3_bucket_target(resources)
                    if not bucket:
                        ok, msg = False, "Could not determine S3 bucket target from finding resources"
                    else:
                        ok, msg = remediate_s3_public_access_block(s3, bucket, dry_run)

                else:
                    ok, msg = False, f"UNSUPPORTED_ACTION: {action_name}"
                    results["spec"]["summary"]["unsupported"] += 1

            except Exception as e:
                ok, msg = False, f"ERROR: {type(e).__name__}: {e}"

            if ok:
                results["spec"]["summary"]["succeeded"] += 1
            else:
                # If it was not already counted as unsupported, count as failed
                if not msg.startswith("UNSUPPORTED_ACTION"):
                    results["spec"]["summary"]["failed"] += 1

        else:
            # Not executed (manual/ignore/other)
            if decision_type == "IGNORE":
                msg = "IGNORED"
                results["spec"]["summary"]["ignored"] += 1
            elif decision_type == "MANUAL":
                msg = "MANUAL_REQUIRED"
                results["spec"]["summary"]["manual_required"] += 1
            else:
                msg = f"NOT_EXECUTED (decision={decision_type}, action={action_name})"
                results["spec"]["summary"]["not_executed"] += 1

        results["spec"]["results"].append(
            {
                "itemId": item.get("id"),
                "findingId": finding_norm.get("findingId"),
                "title": finding_norm.get("title"),
                "decision": decision_type,
                "action": action_name,
                "ok": ok,
                "message": msg,
            }
        )

    out_dir = os.path.join(args.output_dir, executed_at)
    ensure_directory(out_dir)

    out_path = os.path.join(out_dir, "remediation_results.yaml")
    with open(out_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(results, f, sort_keys=False, allow_unicode=True)

    print(f"[OK] Results written: {out_path}")
    print(f" - total items: {results['spec']['summary']['total']}")
    print(f" - executed: {results['spec']['summary']['executed']}")
    print(f" - succeeded: {results['spec']['summary']['succeeded']}")
    print(f" - failed: {results['spec']['summary']['failed']}")
    print(f" - manual_required: {results['spec']['summary']['manual_required']}")
    print(f" - ignored: {results['spec']['summary']['ignored']}")
    print(f" - unsupported: {results['spec']['summary']['unsupported']}")


if __name__ == "__main__":
    main()

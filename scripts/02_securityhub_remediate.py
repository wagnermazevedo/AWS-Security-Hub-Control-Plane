import argparse
import json
from typing import Dict, List

from lib.aws_clients import get_client
from lib.io_utils import ensure_directory, utc_timestamp, write_json


def remediate_s3_public_access_block(s3, bucket: str, dry_run: bool):
    if dry_run:
        return "DRY-RUN: would enable Public Access Block"
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    return "Public Access Block enabled"


def main():
    parser = argparse.ArgumentParser(description="Execute remediation plan")
    parser.add_argument("--region", required=True)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--output-dir", default="outputs")
    args = parser.parse_args()

    plan = json.load(open(args.plan))
    s3 = get_client("s3", region=args.region)

    results = []

    for action in plan["actions"]:
        if action["action"] == "s3_public_access_block":
            bucket = action["resources"][0].split(":::")[-1]
            msg = remediate_s3_public_access_block(s3, bucket, args.dry_run)
            results.append({
                "finding_id": action["finding_id"],
                "action": action["action"],
                "result": msg
            })

    ts = utc_timestamp()
    out_dir = f"{args.output_dir}/{ts}"
    ensure_directory(out_dir)
    write_json(f"{out_dir}/remediation_results.json", results)

    print(f"[OK] Remediation completed: {out_dir}")


if __name__ == "__main__":
    main()

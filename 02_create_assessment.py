#!/usr/bin/env python3
import argparse, json, os
from datetime import datetime, timezone
import boto3

def utc_ts():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

def main():
    ap = argparse.ArgumentParser(description="Create Audit Manager assessment from a framework.")
    ap.add_argument("--region", default=os.getenv("AWS_REGION", "us-east-1"))
    ap.add_argument("--assessment-name", default=f"ISO22301-Assessment-{utc_ts()}")
    ap.add_argument("--framework-id", required=True)
    ap.add_argument("--description", default="ISO 22301 emulation assessment (AWS evidence import).")
    ap.add_argument("--roles", nargs="+", default=[], help="Optional: AWS account roles (string) for audit manager roles")
    args = ap.parse_args()

    audit = boto3.client("auditmanager", region_name=args.region)

    # Minimal scope: all accounts in current context (you can refine)
    scope = {
        "awsAccounts": [{"id": boto3.client("sts").get_caller_identity()["Account"]}],
        "awsServices": []  # can be populated; leaving empty is acceptable for manual evidence import approach
    }

    resp = audit.create_assessment(
        name=args.assessment_name,
        description=args.description,
        assessmentReportsDestination={
            # You can set this later via UpdateAssessment if you want
            "destinationType": "S3"
        },
        scope=scope,
        roles=[{"roleType": "PROCESS_OWNER", "roleArn": r} for r in args.roles] if args.roles else [],
        frameworkId=args.framework_id
    )

    out = {
        "region": args.region,
        "assessment_name": args.assessment_name,
        "assessment_id": resp["assessment"]["id"],
        "assessment_arn": resp["assessment"]["arn"],
        "framework_id": args.framework_id
    }
    print(json.dumps(out, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()

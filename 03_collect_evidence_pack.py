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

def dump(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False, default=str)

def s3_put(region, bucket, key, file_path):
    s3 = boto3.client("s3", region_name=region)
    with open(file_path, "rb") as f:
        s3.put_object(Bucket=bucket, Key=key, Body=f)

def call_api(service, operation, region):
    # route53 is global; securityhub/guardduty/iam/org etc vary
    if service in ("route53", "iam", "organizations"):
        client = boto3.client(service)
    else:
        client = boto3.client(service, region_name=region)
    fn = getattr(client, operation[0].lower() + operation[1:])  # DescribeTrails -> describe_trails
    return fn()

def parse_call(call_str):
    # "cloudtrail:DescribeTrails"
    svc, op = call_str.split(":")
    return svc, op

def main():
    ap = argparse.ArgumentParser(description="Collect AWS evidence + external placeholders (versioned pack).")
    ap.add_argument("--region", default=os.getenv("AWS_REGION", "us-east-1"))
    ap.add_argument("--yaml", required=True)
    ap.add_argument("--outdir", default="outputs")
    ap.add_argument("--s3-bucket", default=None)
    ap.add_argument("--s3-prefix", default="iso22301/evidence")
    args = ap.parse_args()

    spec = load_yaml(args.yaml)
    ts = utc_ts()

    aws_collected = {}
    external_required = {}

    # Collect AWS/securityhub calls declared in YAML
    for c in spec["controls"]:
        cid = c["id"]
        for ev in c.get("evidence", []):
            ev_type = ev.get("type")

            if ev_type in ("aws_api", "securityhub"):
                for call in ev.get("calls", []):
                    svc, op = parse_call(call)
                    key = f"{cid}:{call}"
                    try:
                        aws_collected[key] = {
                            "service": svc,
                            "operation": op,
                            "response": call_api(svc, op, args.region)
                        }
                    except Exception as e:
                        aws_collected[key] = {
                            "service": svc,
                            "operation": op,
                            "error": str(e)
                        }

            elif ev_type == "external":
                external_required[cid] = ev.get("required_artifacts", [])

    pack = {
        "meta": {
            "timestamp_utc": ts,
            "region": args.region,
            "spec_name": spec.get("name"),
            "spec_version": spec.get("version"),
        },
        "aws_collected": aws_collected,
        "external_required": external_required,
    }

    outfile = os.path.join(args.outdir, f"evidence_pack_{args.region}_{ts}.json")
    dump(outfile, pack)
    print(f"[OK] Evidence pack created: {outfile}")

    if args.s3_bucket:
        key = f"{args.s3_prefix}/{args.region}/packs/evidence_pack_{ts}.json"
        s3_put(args.region, args.s3_bucket, key, outfile)
        print(f"[OK] Uploaded pack to s3://{args.s3_bucket}/{key}")

        # external evidence folder convention
        ext_prefix = f"{args.s3_prefix}/{args.region}/external/{ts}/"
        print("[INFO] Upload external artifacts under:")
        print(f"       s3://{args.s3_bucket}/{ext_prefix}")
        print("       (e.g., BCP-EXT-DR-TEST-01/DR_test_report.pdf)")

if __name__ == "__main__":
    main()

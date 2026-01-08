import argparse
import csv
import os
from typing import Dict, List

from lib.aws_clients import get_client
from lib.io_utils import (
    compact_finding,
    ensure_directory,
    utc_timestamp,
    write_json,
    write_jsonl,
)


def paginate_findings(securityhub, filters: Dict, limit: int) -> List[Dict]:
    findings = []
    paginator = securityhub.get_paginator("get_findings")

    for page in paginator.paginate(Filters=filters, PaginationConfig={"PageSize": 100}):
        for f in page.get("Findings", []):
            findings.append(f)
            if len(findings) >= limit:
                return findings
    return findings


def list_enabled_standards(securityhub):
    standards = []
    paginator = securityhub.get_paginator("get_enabled_standards")
    for page in paginator.paginate():
        standards.extend(page.get("StandardsSubscriptions", []))
    return standards


def list_controls(securityhub, subscription_arn: str):
    controls = []
    paginator = securityhub.get_paginator("describe_standards_controls")
    for page in paginator.paginate(StandardsSubscriptionArn=subscription_arn):
        controls.extend(page.get("Controls", []))
    return controls


def main():
    parser = argparse.ArgumentParser(description="Security Hub Control Plane - Scan")
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile")
    parser.add_argument("--output-dir", default="outputs")
    parser.add_argument("--severity", default="HIGH,CRITICAL")
    parser.add_argument("--compliance", default="FAILED")
    parser.add_argument("--limit", type=int, default=2000)
    args = parser.parse_args()

    sh = get_client("securityhub", region=args.region, profile=args.profile)

    timestamp = utc_timestamp()
    run_dir = os.path.join(args.output_dir, timestamp)
    ensure_directory(run_dir)

    severity_filters = [
        {"Value": s.strip(), "Comparison": "EQUALS"}
        for s in args.severity.split(",")
    ]

    filters = {
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "ComplianceStatus": [{"Value": args.compliance, "Comparison": "EQUALS"}],
        "SeverityLabel": severity_filters,
    }

    findings = paginate_findings(sh, filters, args.limit)
    compact = [compact_finding(f) for f in findings]

    write_jsonl(f"{run_dir}/findings.jsonl", compact)
    write_json(f"{run_dir}/metadata.json", {
        "timestamp": timestamp,
        "region": args.region,
        "total_findings": len(compact),
        "filters": filters,
    })

    with open(f"{run_dir}/findings.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "Id", "AwsAccountId", "Region", "SeverityLabel",
                "ComplianceStatus", "Title"
            ],
            delimiter=";"
        )
        writer.writeheader()
        for row in compact:
            writer.writerow({k: row.get(k) for k in writer.fieldnames})

    standards = list_enabled_standards(sh)
    controls_dump = []

    for s in standards:
        for c in list_controls(sh, s["StandardsSubscriptionArn"]):
            controls_dump.append({
                "StandardsArn": s["StandardsArn"],
                "ControlId": c["ControlId"],
                "ControlStatus": c["ControlStatus"],
                "UpdatedAt": c["UpdatedAt"],
            })

    write_json(f"{run_dir}/controls_status.json", controls_dump)

    print(f"[OK] Scan completed: {run_dir}")


if __name__ == "__main__":
    main()

import argparse
import csv
import os
from typing import Any, Dict, List, Optional

from lib.aws_clients import client
from lib.io_utils import compact_finding, ensure_dir, utc_ts, write_json, write_jsonl


def paginate_get_findings(sh, filters: Dict[str, Any], max_items: int = 2000) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    paginator = sh.get_paginator("get_findings")
    count = 0
    for page in paginator.paginate(Filters=filters, PaginationConfig={"PageSize": 100}):
        for f in page.get("Findings", []):
            findings.append(f)
            count += 1
            if count >= max_items:
                return findings
    return findings


def list_enabled_standards(sh) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    paginator = sh.get_paginator("get_enabled_standards")
    for page in paginator.paginate(PaginationConfig={"PageSize": 50}):
        out.extend(page.get("StandardsSubscriptions", []))
    return out


def describe_controls_for_standard(sh, standards_subscription_arn: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    paginator = sh.get_paginator("describe_standards_controls")
    for page in paginator.paginate(StandardsSubscriptionArn=standards_subscription_arn, PaginationConfig={"PageSize": 100}):
        out.extend(page.get("Controls", []))
    return out


def write_findings_csv(path: str, findings_compact: List[Dict[str, Any]]) -> None:
    ensure_dir(os.path.dirname(path))
    fields = [
        "Id","AwsAccountId","Region","GeneratorId","SeverityLabel","ComplianceStatus",
        "WorkflowStatus","RecordState","Title","CreatedAt","UpdatedAt"
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter=";")
        w.writeheader()
        for r in findings_compact:
            w.writerow({k: r.get(k) for k in fields})


def main():
    ap = argparse.ArgumentParser(description="Security Hub Control Plane - Scan (versioned export)")
    ap.add_argument("--region", required=True)
    ap.add_argument("--profile", default=None)
    ap.add_argument("--outdir", default="outputs")
    ap.add_argument("--max-findings", type=int, default=2000)

    ap.add_argument("--severity", default="HIGH,CRITICAL", help="Comma list (INFORMATIONAL,LOW,MEDIUM,HIGH,CRITICAL)")
    ap.add_argument("--compliance", default="FAILED", help="FAILED|PASSED|WARNING|NOT_AVAILABLE|... (Security Hub Compliance.Status)")
    ap.add_argument("--record-state", default="ACTIVE", help="ACTIVE|ARCHIVED")
    args = ap.parse_args()

    sh = client("securityhub", region=args.region, profile=args.profile)

    run_ts = utc_ts()
    run_dir = os.path.join(args.outdir, run_ts)
    ensure_dir(run_dir)

    sev_list = [s.strip().upper() for s in args.severity.split(",") if s.strip()]
    filters: Dict[str, Any] = {
        "RecordState": [{"Value": args.record_state, "Comparison": "EQUALS"}],
        "ComplianceStatus": [{"Value": args.compliance, "Comparison": "EQUALS"}],
    }
    if sev_list:
        filters["SeverityLabel"] = [{"Value": s, "Comparison": "EQUALS"} for s in sev_list]

    findings = paginate_get_findings(sh, filters=filters, max_items=args.max_findings)
    findings_compact = [compact_finding(f) for f in findings]

    write_json(os.path.join(run_dir, "scan_meta.json"), {
        "timestamp": run_ts,
        "region": args.region,
        "filters": filters,
        "findings_count": len(findings_compact),
    })
    write_jsonl(os.path.join(run_dir, "findings.jsonl"), findings_compact)
    write_findings_csv(os.path.join(run_dir, "findings.csv"), findings_compact)

    # Standards/controls status (evidência adicional de auditoria)
    standards = list_enabled_standards(sh)
    write_json(os.path.join(run_dir, "enabled_standards.json"), standards)

    controls_dump: List[Dict[str, Any]] = []
    for s in standards:
        sub_arn = s.get("StandardsSubscriptionArn")
        if not sub_arn:
            continue
        controls = describe_controls_for_standard(sh, sub_arn)
        for c in controls:
            controls_dump.append({
                "StandardsSubscriptionArn": sub_arn,
                "StandardsArn": s.get("StandardsArn"),
                "StandardsStatus": s.get("StandardsStatus"),
                "ControlId": c.get("ControlId"),
                "ControlStatus": c.get("ControlStatus"),
                "DisabledReason": c.get("DisabledReason"),
                "ControlTitle": c.get("ControlTitle"),
                "ControlDescription": c.get("ControlDescription"),
                "RelatedRequirements": c.get("RelatedRequirements", []),
                "UpdatedAt": c.get("UpdatedAt"),
            })

    write_json(os.path.join(run_dir, "controls_status.json"), controls_dump)

    print(f"[OK] Export concluído: {run_dir}")
    print(f" - findings: {len(findings_compact)}")
    print(f" - standards: {len(standards)}")
    print(f" - controls records: {len(controls_dump)}")


if __name__ == "__main__":
    main()

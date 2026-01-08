import argparse
import os
from typing import Any, Dict, List, Optional

import yaml

from lib.aws_clients import get_client
from lib.io_utils import ensure_directory, utc_timestamp, safe_get


def paginate_findings(securityhub, filters: Dict[str, Any], limit: int) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    paginator = securityhub.get_paginator("get_findings")
    for page in paginator.paginate(Filters=filters, PaginationConfig={"PageSize": 100}):
        for f in page.get("Findings", []):
            findings.append(f)
            if len(findings) >= limit:
                return findings
    return findings


def normalize_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    resources_norm = []
    for r in f.get("Resources", []) or []:
        resources_norm.append({
            "type": r.get("Type"),
            "id": r.get("Id"),
            "region": r.get("Region"),
            "partition": r.get("Partition"),
        })

    return {
        "findingId": f.get("Id"),
        "productArn": f.get("ProductArn"),
        "generatorId": f.get("GeneratorId"),
        "awsAccountId": f.get("AwsAccountId"),
        "region": f.get("Region"),
        "title": f.get("Title"),
        "severityLabel": safe_get(f, "Severity", "Label"),
        "complianceStatus": safe_get(f, "Compliance", "Status"),
        "workflowStatus": safe_get(f, "Workflow", "Status"),
        "recordState": f.get("RecordState"),
        "createdAt": f.get("CreatedAt"),
        "updatedAt": f.get("UpdatedAt"),
        "types": f.get("Types") or [],
        "resources": resources_norm,
    }


def main():
    ap = argparse.ArgumentParser(description="Export Security Hub findings to a universal remediation-ready YAML")
    ap.add_argument("--region", required=True)
    ap.add_argument("--profile", default=None)
    ap.add_argument("--output-dir", default="outputs")
    ap.add_argument("--limit", type=int, default=2000)

    # optional filters (can be empty to export broadly)
    ap.add_argument("--compliance", default="FAILED", help="e.g., FAILED|PASSED|WARNING|NOT_AVAILABLE")
    ap.add_argument("--severity", default="HIGH,CRITICAL", help="Comma list: INFORMATIONAL,LOW,MEDIUM,HIGH,CRITICAL")
    ap.add_argument("--record-state", default="ACTIVE", help="ACTIVE|ARCHIVED")
    args = ap.parse_args()

    sh = get_client("securityhub", region=args.region, profile=args.profile)

    timestamp = utc_timestamp()
    run_dir = os.path.join(args.output_dir, timestamp)
    ensure_directory(run_dir)

    sev_list = [s.strip().upper() for s in args.severity.split(",") if s.strip()]

    filters: Dict[str, Any] = {
        "RecordState": [{"Value": args.record_state, "Comparison": "EQUALS"}],
    }
    if args.compliance:
        filters["ComplianceStatus"] = [{"Value": args.compliance, "Comparison": "EQUALS"}]
    if sev_list:
        filters["SeverityLabel"] = [{"Value": s, "Comparison": "EQUALS"} for s in sev_list]

    findings = paginate_findings(sh, filters=filters, limit=args.limit)

    # Try to infer account id (best-effort)
    account_id = findings[0].get("AwsAccountId") if findings else None

    export = {
        "apiVersion": "shcp/v1",
        "kind": "FindingsExport",
        "metadata": {
            "generatedAt": timestamp,
            "region": args.region,
            "accountId": account_id,
            "source": "securityhub:GetFindings",
            "filters": {
                "RecordState": args.record_state,
                "ComplianceStatus": args.compliance,
                "SeverityLabel": sev_list,
            },
        },
        "spec": {
            "defaultMode": "dry-run",
            "items": [],
        },
    }

    for idx, f in enumerate(findings, start=1):
        export["spec"]["items"].append({
            "id": f"item-{idx:06d}",
            "finding": {
                "normalized": normalize_finding(f),
                "raw": f,  # keep the full finding intact
            },
            "decision": {
                "type": "MANUAL",  # AUTO|MANUAL|IGNORE (default MANUAL for universal export)
                "reason": "Universal export: no action mapping applied",
            },
            "action": {
                "name": "manual",
                "params": {},
            },
            "guardrails": {
                "requireDryRunFirst": True,
                "approval": None,
            },
        })

    out_path = os.path.join(run_dir, "securityhub_findings_export.yaml")
    with open(out_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(export, f, sort_keys=False, allow_unicode=True)

    print(f"[OK] YAML exported: {out_path}")
    print(f" - findings: {len(findings)}")


if __name__ == "__main__":
    main()

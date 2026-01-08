import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Iterable


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def ensure_directory(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_jsonl(path: str, records: Iterable[Dict[str, Any]]) -> None:
    ensure_directory(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_json(path: str, obj: Any) -> None:
    ensure_directory(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def safe_get(data: Dict[str, Any], *keys: str, default=None):
    current = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def compact_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Reduce a Security Hub finding to a stable, audit-friendly evidence record.
    """
    return {
        "Id": finding.get("Id"),
        "ProductArn": finding.get("ProductArn"),
        "GeneratorId": finding.get("GeneratorId"),
        "AwsAccountId": finding.get("AwsAccountId"),
        "Region": finding.get("Region"),
        "CreatedAt": finding.get("CreatedAt"),
        "UpdatedAt": finding.get("UpdatedAt"),
        "SeverityLabel": safe_get(finding, "Severity", "Label"),
        "ComplianceStatus": safe_get(finding, "Compliance", "Status"),
        "WorkflowStatus": safe_get(finding, "Workflow", "Status"),
        "RecordState": finding.get("RecordState"),
        "Title": finding.get("Title"),
        "Description": finding.get("Description"),
        "Types": finding.get("Types", []),
        "Resources": finding.get("Resources", []),
        "ProductFields": finding.get("ProductFields", {}),
    }

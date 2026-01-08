import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional


def utc_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_jsonl(path: str, records: Iterable[Dict[str, Any]]) -> None:
    ensure_dir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def write_json(path: str, obj: Any) -> None:
    ensure_dir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def safe_get(d: Dict[str, Any], *keys: str, default=None):
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def compact_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    """Reduz para um 'registro de evidência' útil e estável."""
    return {
        "Id": f.get("Id"),
        "ProductArn": f.get("ProductArn"),
        "GeneratorId": f.get("GeneratorId"),
        "AwsAccountId": f.get("AwsAccountId"),
        "Region": f.get("Region"),
        "CreatedAt": f.get("CreatedAt"),
        "UpdatedAt": f.get("UpdatedAt"),
        "SeverityLabel": safe_get(f, "Severity", "Label"),
        "ComplianceStatus": safe_get(f, "Compliance", "Status"),
        "WorkflowStatus": safe_get(f, "Workflow", "Status"),
        "RecordState": f.get("RecordState"),
        "Title": f.get("Title"),
        "Description": f.get("Description"),
        "Types": f.get("Types", []),
        "Resources": f.get("Resources", []),
        "ProductFields": f.get("ProductFields", {}),
    }

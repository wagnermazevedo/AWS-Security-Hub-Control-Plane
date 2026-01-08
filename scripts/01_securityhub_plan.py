import argparse
import os
from typing import Any, Dict, List, Optional, Tuple

import yaml

from lib.finding_matchers import match_any_contains
from lib.io_utils import ensure_directory


def load_yaml(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def save_yaml(path: str, data: Dict[str, Any]) -> None:
    ensure_directory(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)


def build_match_blob(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a dict similar enough for match_any_contains(), using normalized + raw content.
    This keeps matching flexible without relying on a single schema.
    """
    finding = item.get("finding", {}) or {}
    normalized = finding.get("normalized", {}) or {}
    raw = finding.get("raw", {}) or {}

    # Prefer normalized fields, fallback to raw
    merged = {
        "GeneratorId": normalized.get("generatorId") or raw.get("GeneratorId"),
        "Title": normalized.get("title") or raw.get("Title"),
        "Description": raw.get("Description") or normalized.get("description"),
        "Types": normalized.get("types") or raw.get("Types") or [],
        "ProductFields": raw.get("ProductFields") or {},
    }
    return merged


def apply_rules_to_item(item: Dict[str, Any], rules: List[Dict[str, Any]]) -> Tuple[str, str, Dict[str, Any]]:
    """
    Returns: (decision_type, action_name, action_params)
    decision_type: AUTO or MANUAL
    """
    blob = build_match_blob(item)

    for rule in rules:
        needles = rule.get("match_contains", []) or []
        if needles and match_any_contains(blob, needles):
            action_name = rule.get("action", "manual")
            action_params = rule.get("params", {}) or {}
            reason = f"Matched rule: {rule.get('name', '<unnamed>')}"
            # update item
            item["decision"] = {"type": "AUTO", "reason": reason}
            item["action"] = {"name": action_name, "params": action_params}
            item["note"] = rule.get("note", "")
            item["matched_rule"] = rule.get("name", "<unnamed>")
            return "AUTO", action_name, action_params

    # no match
    item["decision"] = {"type": "MANUAL", "reason": "No remediation rule matched"}
    item["action"] = {"name": "manual", "params": {}}
    item.pop("matched_rule", None)
    item.pop("note", None)
    return "MANUAL", "manual", {}


def main():
    ap = argparse.ArgumentParser(
        description="Security Hub Control Plane - Promote YAML items to AUTO/MANUAL decisions using remediate_map.yaml"
    )
    ap.add_argument("--input-yaml", required=True, help="Path to the YAML exported by 00_securityhub_scan.py")
    ap.add_argument("--rules", required=True, help="Path to remediate_map.yaml")
    ap.add_argument("--output-yaml", required=True, help="Path to write the planned YAML (YAML only)")
    args = ap.parse_args()

    doc = load_yaml(args.input_yaml)

    with open(args.rules, "r", encoding="utf-8") as f:
        rules_doc = yaml.safe_load(f) or {}
    rules = rules_doc.get("rules", []) or []

    items = (doc.get("spec", {}) or {}).get("items", []) or []
    auto_count = 0
    manual_count = 0

    for item in items:
        decision, action_name, _ = apply_rules_to_item(item, rules)
        if decision == "AUTO":
            auto_count += 1
        else:
            manual_count += 1

    # Write summary metadata (audit-friendly)
    meta = doc.get("metadata", {}) or {}
    doc["metadata"] = meta
    doc["metadata"]["plannedBy"] = "01_securityhub_plan.py"
    doc["metadata"]["planSummary"] = {
        "totalItems": len(items),
        "auto": auto_count,
        "manual": manual_count,
        "rulesFile": args.rules,
    }

    save_yaml(args.output_yaml, doc)

    print(f"[OK] Planned YAML written: {args.output_yaml}")
    print(f" - total items: {len(items)}")
    print(f" - AUTO: {auto_count}")
    print(f" - MANUAL: {manual_count}")


if __name__ == "__main__":
    main()

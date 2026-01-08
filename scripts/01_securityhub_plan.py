import argparse
import json
from typing import Any, Dict, List

import yaml

from lib.io_utils import ensure_dir, safe_get, write_json
from lib.finding_matchers import match_any_contains, resource_ids


def load_jsonl(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def main():
    ap = argparse.ArgumentParser(description="Security Hub Control Plane - Plan (propose actions)")
    ap.add_argument("--input-findings", required=True, help="outputs/<ts>/findings.jsonl")
    ap.add_argument("--remediate-map", required=True, help="config/remediate_map.yaml")
    ap.add_argument("--out-plan", required=True, help="outputs/<ts>/plan.json")
    args = ap.parse_args()

    findings = load_jsonl(args.input_findings)
    with open(args.remediate_map, "r", encoding="utf-8") as f:
        rmap = yaml.safe_load(f)

    rules = rmap.get("rules", [])
    actions: List[Dict[str, Any]] = []

    for fnd in findings:
        blob_hit = None
        matched_rule = None
        for rule in rules:
            needles = rule.get("match_contains", [])
            if needles and match_any_contains(fnd, needles):
                matched_rule = rule
                blob_hit = needles
                break

        if not matched_rule:
            continue

        actions.append({
            "finding_id": fnd.get("Id"),
            "title": fnd.get("Title"),
            "severity": fnd.get("SeverityLabel"),
            "generator_id": fnd.get("GeneratorId"),
            "resources": resource_ids(fnd),
            "proposed_action": matched_rule.get("action"),
            "action_params": matched_rule.get("params", {}),
            "matched_on": blob_hit,
            "note": matched_rule.get("note", ""),
        })

    plan = {
        "input_findings": args.input_findings,
        "actions_count": len(actions),
        "actions": actions,
    }

    ensure_dir("/".join(args.out_plan.split("/")[:-1]))
    write_json(args.out_plan, plan)
    print(f"[OK] Plano gerado: {args.out_plan} ({len(actions)} ações)")


if __name__ == "__main__":
    main()

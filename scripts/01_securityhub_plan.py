import argparse
import json
import yaml
from typing import List, Dict

from lib.finding_matchers import match_any_contains, extract_resource_ids
from lib.io_utils import ensure_directory, write_json


def load_jsonl(path: str) -> List[Dict]:
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def main():
    parser = argparse.ArgumentParser(description="Generate remediation plan from Security Hub findings")
    parser.add_argument("--findings", required=True)
    parser.add_argument("--rules", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    findings = load_jsonl(args.findings)
    rules = yaml.safe_load(open(args.rules))

    actions = []

    for finding in findings:
        for rule in rules["rules"]:
            if match_any_contains(finding, rule["match_contains"]):
                actions.append({
                    "finding_id": finding["Id"],
                    "title": finding["Title"],
                    "severity": finding["SeverityLabel"],
                    "resources": extract_resource_ids(finding),
                    "action": rule["action"],
                    "params": rule.get("params", {}),
                    "note": rule.get("note", "")
                })
                break

    ensure_directory("/".join(args.output.split("/")[:-1]))
    write_json(args.output, {
        "total_actions": len(actions),
        "actions": actions
    })

    print(f"[OK] Remediation plan generated: {args.output}")


if __name__ == "__main__":
    main()

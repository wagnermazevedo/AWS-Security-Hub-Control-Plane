#!/usr/bin/env python3
"""[00] SCAN: lê os findings ativos dos controles do mapa e confere o recurso real. Somente leitura.

Saída (pasta nova por execução, nunca sobrescrita):
  <output-dir>/<timestamp>/securityhub_findings_export.yaml  -> entrada do plan
  <output-dir>/<timestamp>/securityhub_findings_export.json  -> inclui o finding ASFF bruto
  <output-dir>/<timestamp>/securityhub_findings_export.csv   -> Athena
  <output-dir>/<timestamp>/summary.md                        -> gente
"""

import argparse
import os
from collections import Counter

import _bootstrap  # noqa: F401

from lib import API_VERSION
from lib.aws import SERVICES, client, session
from lib.io import DEFAULT_OUTPUTS, markdown_table, new_run_dir, repo_path, utc_timestamp, write_csv, write_json, write_text, write_yaml
from lib.rules import RulesError, load_rules
from scanner.findings import get_failed_findings, normalize
from scanner.resources import COMPLIANT, resource_tags, verify

CSV_FIELDS = ["id", "control", "severity", "workflow_status", "resource_type", "resource", "verified_state", "exception", "updated_at"]


def build_clients(sess):
    return {svc: client(sess, svc) for svc in SERVICES}


def main():
    parser = argparse.ArgumentParser(description="Security Hub Scan (somente leitura)")
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile", default=None)
    parser.add_argument("--rules", default=repo_path("config", "remediate_map.yaml"))
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUTS, help="Padrão: outputs/ do repositório")
    args = parser.parse_args()

    try:
        rules_doc = load_rules(args.rules)
    except RulesError as err:
        raise SystemExit(f"[ERRO] Mapa de controles inválido: {err}")
    controls = rules_doc.get("controls", {}) or {}
    exc_cfg = rules_doc.get("exception", {}) or {}

    clients = build_clients(session(args.profile, args.region))
    account_id = clients["sts"].get_caller_identity()["Account"]

    raw_findings = get_failed_findings(clients["securityhub"], controls.keys())
    items, raw_by_id = [], {}
    for idx, raw in enumerate(raw_findings, start=1):
        norm = normalize(raw)
        control = norm["controlId"]
        locator = norm["resource"]["locator"]
        state, detail = verify(control, clients, account_id, locator)
        item = {
            "id": f"shcp-item-{idx:06d}",
            "control": control,
            "title": (controls.get(control) or {}).get("title", norm["title"]),
            "finding": norm,
            "verified_state": {"state": state, **detail},
        }
        if state == COMPLIANT:
            item["note"] = "O recurso já está conforme; o finding aguarda reavaliação do Security Hub"
        tags = resource_tags(control, clients, locator) if locator else {}
        if exc_cfg.get("tag_key") in tags:
            item["exception"] = {"justification": tags[exc_cfg["tag_key"]],
                                 "owner": tags.get(exc_cfg.get("owner_tag_key", "exception-owner"))}
        items.append(item)
        raw_by_id[item["id"]] = raw

    timestamp = utc_timestamp()
    by_control = Counter(i["control"] for i in items)
    export = {
        "apiVersion": API_VERSION,
        "kind": "SecurityHubFindingsExport",
        "metadata": {
            "generatedAt": timestamp,
            "region": args.region,
            "accountId": account_id,
            "source": "securityhub:GetFindings (ASFF)",
            "rulesFile": os.path.relpath(args.rules, repo_path()),
            "controls": list(controls.keys()),
            "controlFiles": rules_doc.get("included", []),
            "summary": dict(by_control),
        },
        "spec": {"defaultMode": "dry-run", "items": items},
    }

    out_dir = new_run_dir(args.output_dir, timestamp)
    write_yaml(os.path.join(out_dir, "securityhub_findings_export.yaml"), export)
    write_json(os.path.join(out_dir, "securityhub_findings_export.json"),
               {**export, "raw": raw_by_id})
    rows = [{
        "id": i["id"], "control": i["control"], "severity": i["finding"]["severity"],
        "workflow_status": i["finding"]["workflowStatus"], "resource_type": i["finding"]["resource"]["type"],
        "resource": i["finding"]["resource"]["locator"] or "conta", "verified_state": i["verified_state"]["state"],
        "exception": "sim" if i.get("exception") else "", "updated_at": i["finding"]["updatedAt"],
    } for i in items]
    write_csv(os.path.join(out_dir, "securityhub_findings_export.csv"), rows, CSV_FIELDS)
    write_text(os.path.join(out_dir, "summary.md"),
               f"# Security Hub Scan · {timestamp}\n\nConta `{account_id}` · região `{args.region}`\n\n"
               + markdown_table(rows, ["control", "severity", "resource", "verified_state", "workflow_status", "exception"]))

    print(f"[OK] Security Hub Scan concluído: {out_dir}/securityhub_findings_export.yaml")
    print(f" - Findings ativos com falha: {len(items)}")
    for row in rows:
        print(f"   {row['control']:<6} {row['severity'] or '-':<9} {row['resource']:<40} verified_state={row['verified_state']}")


if __name__ == "__main__":
    main()

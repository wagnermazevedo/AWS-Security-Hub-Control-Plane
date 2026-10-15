#!/usr/bin/env python3
"""[02] REMEDIATE: executa o plano. Dry-run é o padrão.

Para cada item:
  1. busca de novo o finding ativo no Security Hub (o plano pode estar velho ou anonimizado);
  2. AUTO: confere o recurso, corrige, confere de novo e só então marca o finding RESOLVED;
  3. MANUAL: marca o finding NOTIFIED, com nota e runbook;
  4. SUPPRESS: marca o finding SUPPRESSED, com justificativa e dono.
Em dry-run nenhuma API de escrita é chamada, nem no recurso nem no Security Hub.

Saída: <output-dir>/<timestamp>/securityhub_remediation_results.{json,csv} e summary.md.
(Não grava YAML de propósito: o test-control-plane.sh procura o YAML de scan mais recente.)
"""

import argparse
import os

import _bootstrap  # noqa: F401

from lib import API_VERSION
from lib.aws import client, session
from lib.io import load_yaml, markdown_table, new_run_dir, utc_timestamp, write_csv, write_json, write_text
from remediate import REGISTRY
from scanner.findings import find_current
from scanner.resources import COMPLIANT, verify

CSV_FIELDS = ["itemId", "control", "decision", "resource", "ok", "workflow", "message"]
MASK = "123456789012"  # valor que o test-control-plane.sh usa para anonimizar contas
UPDATED_BY = "aws-security-hub-control-plane"


def update_workflow(securityhub, finding, status, note):
    response = securityhub.batch_update_findings(
        FindingIdentifiers=[{"Id": finding["findingId"], "ProductArn": finding["productArn"]}],
        Workflow={"Status": status},
        Note={"Text": note[:512], "UpdatedBy": UPDATED_BY},
    )
    unprocessed = response.get("UnprocessedFindings", [])
    if unprocessed:
        raise RuntimeError(f"BatchUpdateFindings não processou: {unprocessed[0].get('ErrorMessage')}")


def handle(item, clients, ctx, run_id, dry_run):
    control = item["control"]
    decision = item["decision"]["type"]
    locator = item["finding"]["resource"]["locator"]
    reason = item["decision"].get("reason", "")

    if locator and MASK in locator:
        return {"ok": False, "workflow": None, "changes": [],
                "message": "REFUSED: o recurso está anonimizado no plano; rode o scan direto, sem anonimização"}

    current = find_current(clients["securityhub"], control, locator)
    if not current:
        return {"ok": True, "workflow": None, "changes": [], "message": "NOOP: o finding não está mais ativo"}

    if decision in ("MANUAL", "SUPPRESS"):
        status = "NOTIFIED" if decision == "MANUAL" else "SUPPRESSED"
        if current["workflowStatus"] == status:
            return {"ok": True, "workflow": status, "changes": [], "message": f"NOOP: finding já está {status}"}
        if dry_run:
            return {"ok": True, "workflow": status, "changes": [], "message": f"DRY-RUN: marcaria o finding {status} · {reason}"}
        update_workflow(clients["securityhub"], current, status, f"[{run_id}] {reason}")
        return {"ok": True, "workflow": status, "changes": [], "message": f"OK: finding {status} · {reason}"}

    # AUTO
    handler = REGISTRY.get(item["action"]["name"])
    if not handler:
        return {"ok": False, "workflow": None, "changes": [], "message": f"UNSUPPORTED_ACTION: {item['action']['name']}"}

    state, _ = verify(control, clients, ctx["account_id"], locator)
    if state == COMPLIANT:
        outcome = {"ok": True, "changes": [], "message": "NOOP: o recurso já está conforme"}
    else:
        outcome = handler(clients, {**ctx, "locator": locator}, dry_run)
        if not outcome["ok"]:
            return {**outcome, "workflow": None}

    if dry_run:
        return {**outcome, "workflow": "RESOLVED", "message": outcome["message"] + " · marcaria o finding RESOLVED"}

    after, detail = verify(control, clients, ctx["account_id"], locator)
    if after != COMPLIANT:
        return {**outcome, "ok": False, "workflow": None,
                "message": outcome["message"] + f" · VERIFY_FAILED: {detail}"}
    update_workflow(clients["securityhub"], current, "RESOLVED",
                    f"[{run_id}] Corrigido e verificado pelo AWS Security Hub Control Plane ({control})")
    return {**outcome, "workflow": "RESOLVED", "message": outcome["message"] + " · VERIFIED · finding RESOLVED"}


def main():
    parser = argparse.ArgumentParser(description="Security Hub Remediate")
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile", default=None)
    parser.add_argument("--yaml", required=True, help="Plano gerado pelo 01_securityhub_plan.py")
    parser.add_argument("--mode", choices=["dry-run", "apply"], default="dry-run")
    parser.add_argument("--output-dir", default="outputs")
    args = parser.parse_args()

    plan = load_yaml(args.yaml)
    if plan.get("kind") != "SecurityHubRemediationPlan":
        raise SystemExit(f"[ERRO] {args.yaml} não é um plano (kind={plan.get('kind')}). Rode o 01_securityhub_plan.py")

    dry_run = args.mode == "dry-run"
    sess = session(args.profile, args.region)
    clients = {svc: client(sess, svc) for svc in ("securityhub", "s3", "s3control", "ec2", "iam", "sts")}
    # A conta vem sempre da credencial em uso, nunca do arquivo (que pode estar anonimizado).
    ctx = {"account_id": clients["sts"].get_caller_identity()["Account"], "region": args.region}

    timestamp = utc_timestamp()
    run_id = f"shcp-{timestamp}"
    items = (plan.get("spec") or {}).get("items", []) or []
    summary = {"total": len(items), "executed": 0, "succeeded": 0, "failed": 0, "noAction": 0}
    results = []

    for item in items:
        decision = (item.get("decision") or {}).get("type", "MANUAL")
        entry = {"itemId": item.get("id"), "control": item.get("control"), "decision": decision,
                 "resource": item["finding"]["resource"]["locator"] or "conta"}
        if decision == "NO_ACTION":
            summary["noAction"] += 1
            entry.update(ok=True, workflow=None, message="NO_ACTION: " + item["decision"].get("reason", ""), changes=[])
        else:
            summary["executed"] += 1
            try:
                outcome = handle(item, clients, ctx, run_id, dry_run)
            except Exception as err:  # registra e segue: um item quebrado não para os outros
                outcome = {"ok": False, "workflow": None, "changes": [], "message": f"ERROR: {err}"}
            summary["succeeded" if outcome["ok"] else "failed"] += 1
            entry.update(outcome)
        results.append(entry)

    out = {
        "apiVersion": API_VERSION,
        "kind": "SecurityHubRemediationResults",
        "metadata": {"executedAt": timestamp, "runId": run_id, "region": args.region, "mode": args.mode,
                     "sourcePlan": os.path.abspath(args.yaml)},
        "spec": {"summary": summary, "results": results},
    }
    out_dir = new_run_dir(args.output_dir, timestamp)
    write_json(os.path.join(out_dir, "securityhub_remediation_results.json"), out)
    write_csv(os.path.join(out_dir, "securityhub_remediation_results.csv"), results, CSV_FIELDS)
    write_text(os.path.join(out_dir, "summary.md"),
               f"# Security Hub Remediate · {args.mode.upper()} · {timestamp}\n\n"
               + "\n".join(f"- {k}: {v}" for k, v in summary.items()) + "\n\n"
               + markdown_table(results, ["control", "decision", "resource", "ok", "workflow", "message"]))

    print(f"[OK] Remediação finalizada ({args.mode.upper()}): {out_dir}")
    for key, value in summary.items():
        print(f" - {key:<10}: {value}")
    for r in results:
        print(f"   {r['control']:<6} {r['decision']:<10} {str(r['resource']):<40} {r['message']}")
    if summary["failed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()

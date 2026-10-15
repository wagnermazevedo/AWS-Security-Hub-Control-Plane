#!/usr/bin/env python3
"""[01] PLAN: cruza cada finding com o remediate_map.yaml pelo ID do controle. Não chama a AWS.

Decisões possíveis por item:
  AUTO       -> o remediate corrige e marca o finding RESOLVED
  MANUAL     -> o remediate marca o finding NOTIFIED, com nota
  SUPPRESS   -> exceção com dono, ou controle suprimido no mapa: finding SUPPRESSED, com nota
  NO_ACTION  -> o recurso já está conforme; o finding aguarda reavaliação
"""

import argparse
import os
from typing import Any, Dict, Tuple

import _bootstrap  # noqa: F401

from lib import API_VERSION
from lib.io import load_yaml, write_yaml
from scanner.resources import COMPLIANT, UNKNOWN

EXPECTED = {
    "S3.1": "Block Public Access da conta com as 4 flags ligadas",
    "S3.8": "Block Public Access do bucket com as 4 flags ligadas",
    "EC2.2": "Security group default sem regras de entrada e saída",
    "EC2.7": "Criptografia de EBS por padrão ligada na região",
}


def decide(item: Dict[str, Any], controls: Dict[str, Any], exc_cfg: Dict[str, Any]) -> Tuple[str, str, str]:
    """Devolve (decisão, motivo, ação)."""
    control = item.get("control")
    rule = controls.get(control)
    state = (item.get("verified_state") or {}).get("state")

    if not rule:
        return "MANUAL", f"Controle {control} não está no remediate_map.yaml", "manual"

    exception = item.get("exception")
    if exception:
        if exception.get("owner"):
            return ("SUPPRESS", f"Exceção ({exc_cfg.get('tag_key')}): {exception.get('justification')} "
                                f"· dono: {exception['owner']}", "none")
        return "MANUAL", "Exceção sem dono não vale: adicione a tag " + exc_cfg.get("owner_tag_key", "exception-owner"), "manual"

    if state == COMPLIANT:
        return "NO_ACTION", "Recurso já conforme; o finding aguarda reavaliação do Security Hub", "none"
    if state == UNKNOWN:
        return "MANUAL", "Não foi possível verificar o recurso: " + str((item.get("verified_state") or {}).get("error")), "manual"

    decision = rule.get("decision", "MANUAL")
    if decision == "AUTO":
        return "AUTO", f"Regra {control}: {rule.get('title', '')}", rule.get("action", "manual")
    if decision == "SUPPRESS":
        return "SUPPRESS", rule.get("reason", "Controle suprimido no mapa"), "none"
    reason = rule.get("reason", "Mapa define tratamento manual")
    if rule.get("runbook"):
        reason += f" · runbook: {rule['runbook']}"
    return "MANUAL", reason, "manual"


def main():
    parser = argparse.ArgumentParser(description="Security Hub Plan (não altera recursos)")
    parser.add_argument("--input-yaml", required=True, help="YAML gerado pelo 00_securityhub_scan.py")
    parser.add_argument("--rules", required=True, help="Caminho do config/remediate_map.yaml")
    parser.add_argument("--output-yaml", required=True, help="Caminho do plano gerado")
    args = parser.parse_args()

    doc = load_yaml(args.input_yaml)
    if doc.get("kind") != "SecurityHubFindingsExport":
        raise SystemExit(f"[ERRO] {args.input_yaml} não é um export de scan (kind={doc.get('kind')})")

    rules_doc = load_yaml(args.rules)
    controls = rules_doc.get("controls", {}) or {}
    exc_cfg = rules_doc.get("exception", {}) or {}

    items = (doc.get("spec") or {}).get("items", []) or []
    counts = {"AUTO": 0, "MANUAL": 0, "SUPPRESS": 0, "NO_ACTION": 0}
    for item in items:
        decision, reason, action = decide(item, controls, exc_cfg)
        counts[decision] += 1
        item["decision"] = {"type": decision, "reason": reason}
        item["action"] = {"name": action, "params": {}}
        if decision == "AUTO":
            item["expected_state"] = EXPECTED.get(item["control"], "conforme")
            note = (controls.get(item["control"]) or {}).get("note")
            if note:
                item["action"]["note"] = note

    plan = {
        "apiVersion": API_VERSION,
        "kind": "SecurityHubRemediationPlan",
        "metadata": {
            **(doc.get("metadata") or {}),
            "plannedBy": "01_securityhub_plan.py",
            "sourceScan": os.path.abspath(args.input_yaml),
            "rulesFile": args.rules,
            "planSummary": {"totalItems": len(items), **{k.lower(): v for k, v in counts.items()}},
        },
        "spec": {"defaultMode": "dry-run", "items": items},
    }
    write_yaml(args.output_yaml, plan)

    print(f"[OK] Plano gerado: {args.output_yaml}")
    print(f" - Total     : {len(items)}")
    for key in counts:
        print(f" - {key:<10}: {counts[key]}")
    print("\n Preview do impacto (estado atual -> esperado):")
    for item in items:
        resource = item["finding"]["resource"]["locator"] or "conta"
        target = item.get("expected_state") or item["decision"]["type"].lower()
        print(f"   {item['control']:<6} {item['decision']['type']:<10} {resource:<40} "
              f"{item['verified_state']['state']} -> {target}")


if __name__ == "__main__":
    main()

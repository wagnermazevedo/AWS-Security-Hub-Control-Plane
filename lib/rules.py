"""Carga do mapa de controles: o remediate_map.yaml e os arquivos que ele inclui.

O remediate_map.yaml guarda o que vale para todos (exceções) e uma lista
`include` com padrões de arquivo, relativos à pasta do próprio mapa. Cada
arquivo incluído descreve UM controle:

    id: S3.8
    title: "S3 Block Public Access habilitado no bucket"
    decision: AUTO
    action: s3_bucket_public_access_block
    severity: HIGH

Controles também podem ficar direto em `controls:` no próprio mapa. Um mesmo ID
definido duas vezes é erro, para ninguém sobrescrever um controle sem perceber.
"""

import glob
import os
from typing import Any, Dict, List

from lib.io import load_yaml

DECISIONS = ("AUTO", "MANUAL", "SUPPRESS")


class RulesError(ValueError):
    pass


def _check(control_id: str, rule: Dict[str, Any], source: str) -> None:
    decision = rule.get("decision")
    if decision not in DECISIONS:
        raise RulesError(f"{source}: {control_id} tem decision={decision!r}; use {', '.join(DECISIONS)}")
    if decision == "AUTO" and not rule.get("action"):
        raise RulesError(f"{source}: {control_id} é AUTO mas não tem action")


def _add(controls: Dict[str, Any], origin: Dict[str, str], control_id: str, rule: Dict[str, Any], source: str) -> None:
    if not control_id:
        raise RulesError(f"{source}: controle sem id")
    if control_id in controls:
        raise RulesError(f"{control_id} definido duas vezes: em {origin[control_id]} e em {source}")
    _check(control_id, rule, source)
    controls[control_id] = rule
    origin[control_id] = source


def load_rules(path: str) -> Dict[str, Any]:
    """Devolve o mapa com `controls` já juntando os inline e os incluídos.

    Também devolve `sources` (controle -> arquivo de origem) e `included`
    (arquivos lidos), que o scan grava nos metadados do export.
    """
    doc = load_yaml(path)
    base = os.path.dirname(os.path.abspath(path))
    controls: Dict[str, Any] = {}
    origin: Dict[str, str] = {}

    for control_id, rule in (doc.get("controls") or {}).items():
        _add(controls, origin, control_id, dict(rule or {}), os.path.basename(path))

    included: List[str] = []
    for pattern in doc.get("include") or []:
        files = sorted(glob.glob(os.path.join(base, pattern)))
        if not files:
            raise RulesError(f"include '{pattern}' não encontrou nenhum arquivo em {base}")
        for f in files:
            rel = os.path.relpath(f, base)
            rule = dict(load_yaml(f) or {})
            if rule.pop("enabled", True) is False:
                continue
            _add(controls, origin, rule.pop("id", None), rule, rel)
            included.append(rel)

    doc["controls"] = controls
    doc["sources"] = origin
    doc["included"] = included
    return doc

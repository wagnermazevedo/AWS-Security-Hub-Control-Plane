from typing import Any, Dict, List, Optional


def finding_text_blob(f: Dict[str, Any]) -> str:
    parts: List[str] = []
    for k in ("GeneratorId", "Title", "Description"):
        v = f.get(k)
        if v:
            parts.append(str(v))
    pf = f.get("ProductFields") or {}
    for k in ("StandardsArn", "StandardsSubscriptionArn", "ControlId", "RuleId"):
        if k in pf and pf[k]:
            parts.append(str(pf[k]))
    for t in (f.get("Types") or []):
        parts.append(str(t))
    return " | ".join(parts).lower()


def match_any_contains(f: Dict[str, Any], needles: List[str]) -> bool:
    blob = finding_text_blob(f)
    return any(n.lower() in blob for n in needles if n)


def resource_ids(f: Dict[str, Any]) -> List[str]:
    ids = []
    for r in (f.get("Resources") or []):
        rid = r.get("Id")
        if rid:
            ids.append(rid)
    return ids

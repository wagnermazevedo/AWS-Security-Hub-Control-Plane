from typing import Dict, List


def finding_text_blob(finding: Dict) -> str:
    parts: List[str] = []

    for field in ("GeneratorId", "Title", "Description"):
        value = finding.get(field)
        if value:
            parts.append(str(value))

    product_fields = finding.get("ProductFields") or {}
    for key in ("StandardsArn", "StandardsSubscriptionArn", "ControlId", "RuleId"):
        if product_fields.get(key):
            parts.append(str(product_fields[key]))

    for t in finding.get("Types", []):
        parts.append(str(t))

    return " | ".join(parts).lower()


def match_any_contains(finding: Dict, keywords: List[str]) -> bool:
    blob = finding_text_blob(finding)
    return any(keyword.lower() in blob for keyword in keywords)


def extract_resource_ids(finding: Dict) -> List[str]:
    ids = []
    for r in finding.get("Resources", []):
        if r.get("Id"):
            ids.append(r["Id"])
    return ids

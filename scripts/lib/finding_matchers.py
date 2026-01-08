from typing import Any, Dict, List


def finding_text_blob(finding: Dict[str, Any]) -> str:
    """
    Build a normalized text blob used to match remediation rules.
    """
    parts: List[str] = []

    for field in ("GeneratorId", "Title", "Description"):
        value = finding.get(field)
        if value:
            parts.append(str(value))

    product_fields = finding.get("ProductFields") or {}
    for key in ("StandardsArn", "StandardsSubscriptionArn", "ControlId", "RuleId"):
        if product_fields.get(key):
            parts.append(str(product_fields[key]))

    for finding_type in finding.get("Types", []):
        parts.append(str(finding_type))

    return " | ".join(parts).lower()


def match_any_contains(finding: Dict[str, Any], keywords: List[str]) -> bool:
    blob = finding_text_blob(finding)
    return any(keyword.lower() in blob for keyword in keywords if keyword)


def extract_resource_ids(finding: Dict[str, Any]) -> List[str]:
    ids = []
    for resource in finding.get("Resources", []):
        resource_id = resource.get("Id")
        if resource_id:
            ids.append(resource_id)
    return ids

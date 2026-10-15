"""Leitura de findings do Security Hub em ASFF.

Todo o conhecimento do formato ASFF mora neste arquivo. Se a fonte mudar
(por exemplo, para OCSF no Security Lake ou na nova geração do Security Hub),
troca-se este leitor e o plan e o remediate continuam iguais.
"""

from typing import Any, Dict, Iterable, List, Optional

ACTIVE_WORKFLOW = ("NEW", "NOTIFIED")


def control_id(finding: Dict[str, Any]) -> Optional[str]:
    """ID do controle: campo consolidado primeiro, formatos legados depois."""
    compliance = finding.get("Compliance") or {}
    if compliance.get("SecurityControlId"):
        return compliance["SecurityControlId"]
    fields = finding.get("ProductFields") or {}
    if fields.get("ControlId"):
        return fields["ControlId"]
    generator = finding.get("GeneratorId") or ""
    if "/" in generator:
        return generator.rsplit("/", 1)[-1]
    return None


def resource_locator(resource: Dict[str, Any]) -> Optional[str]:
    """Identificador estável do recurso, sem número de conta (ex.: nome do bucket, sg-...)."""
    rtype = resource.get("Type")
    rid = resource.get("Id") or ""
    if rtype == "AwsS3Bucket":
        return rid.split(":::")[-1] if ":::" in rid else rid
    if rtype == "AwsEc2SecurityGroup":
        details = (resource.get("Details") or {}).get("AwsEc2SecurityGroup") or {}
        if details.get("GroupId"):
            return details["GroupId"]
        return rid.split("security-group/")[-1] if "security-group/" in rid else rid
    return None  # controles de conta (S3.1, EC2.7, IAM.4) não têm recurso próprio


def normalize(finding: Dict[str, Any]) -> Dict[str, Any]:
    resource = (finding.get("Resources") or [{}])[0]
    return {
        "findingId": finding.get("Id"),
        "productArn": finding.get("ProductArn"),
        "controlId": control_id(finding),
        "title": finding.get("Title"),
        "severity": (finding.get("Severity") or {}).get("Label"),
        "complianceStatus": (finding.get("Compliance") or {}).get("Status"),
        "workflowStatus": (finding.get("Workflow") or {}).get("Status"),
        "recordState": finding.get("RecordState"),
        "region": finding.get("Region"),
        "accountId": finding.get("AwsAccountId"),
        "updatedAt": finding.get("UpdatedAt"),
        "resource": {
            "type": resource.get("Type"),
            "id": resource.get("Id"),
            "locator": resource_locator(resource),
        },
    }


def failed_findings_filter(control_ids: Iterable[str]) -> Dict[str, Any]:
    return {
        "ComplianceSecurityControlId": [{"Value": c, "Comparison": "EQUALS"} for c in control_ids],
        "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "WorkflowStatus": [{"Value": s, "Comparison": "EQUALS"} for s in ACTIVE_WORKFLOW],
    }


def get_failed_findings(securityhub, control_ids: Iterable[str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    paginator = securityhub.get_paginator("get_findings")
    for page in paginator.paginate(Filters=failed_findings_filter(list(control_ids)),
                                   PaginationConfig={"PageSize": 100}):
        findings.extend(page.get("Findings", []))
    return findings


def find_current(securityhub, control: str, locator: Optional[str]) -> Optional[Dict[str, Any]]:
    """Busca de novo o finding ativo deste controle e recurso. O plano pode estar velho
    (ou anonimizado pelo orquestrador), então o remediate nunca confia no ID do arquivo."""
    for finding in get_failed_findings(securityhub, [control]):
        norm = normalize(finding)
        if norm["resource"]["locator"] == locator:
            return norm
    return None

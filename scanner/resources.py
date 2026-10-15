"""Estado real dos recursos (somente leitura).

O finding diz o que o Security Hub viu na última avaliação; esta camada diz
como o recurso está agora. O scan grava os dois, e o remediate confere de novo
antes e depois de agir.
"""

from typing import Any, Dict, Tuple

from botocore.exceptions import ClientError

COMPLIANT, NONCOMPLIANT, UNKNOWN = "compliant", "noncompliant", "unknown"
BPA_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")

State = Tuple[str, Dict[str, Any]]


def _code(err: ClientError) -> str:
    return err.response.get("Error", {}).get("Code", "")


def _bpa_state(config: Dict[str, Any]) -> State:
    flags = {k: bool(config.get(k)) for k in BPA_KEYS}
    return (COMPLIANT if all(flags.values()) else NONCOMPLIANT), flags


def s3_account_bpa(clients, account_id: str, locator=None) -> State:
    try:
        config = clients["s3control"].get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"]
    except ClientError as err:
        if _code(err) == "NoSuchPublicAccessBlockConfiguration":
            return NONCOMPLIANT, {k: False for k in BPA_KEYS}
        raise
    return _bpa_state(config)


def s3_bucket_bpa(clients, account_id: str, locator: str) -> State:
    try:
        config = clients["s3"].get_public_access_block(Bucket=locator)["PublicAccessBlockConfiguration"]
    except ClientError as err:
        if _code(err) == "NoSuchPublicAccessBlockConfiguration":
            return NONCOMPLIANT, {k: False for k in BPA_KEYS}
        if _code(err) in ("NoSuchBucket", "404"):
            return UNKNOWN, {"error": "bucket não existe mais"}
        raise
    return _bpa_state(config)


def ec2_default_sg(clients, account_id: str, locator: str) -> State:
    try:
        group = clients["ec2"].describe_security_groups(GroupIds=[locator])["SecurityGroups"][0]
    except ClientError as err:
        if _code(err) == "InvalidGroup.NotFound":
            return UNKNOWN, {"error": "security group não existe mais"}
        raise
    state = {
        "groupName": group.get("GroupName"),
        "ingressRules": len(group.get("IpPermissions", [])),
        "egressRules": len(group.get("IpPermissionsEgress", [])),
    }
    ok = state["ingressRules"] == 0 and state["egressRules"] == 0
    return (COMPLIANT if ok else NONCOMPLIANT), state


def ec2_ebs_default(clients, account_id: str, locator=None) -> State:
    enabled = clients["ec2"].get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
    return (COMPLIANT if enabled else NONCOMPLIANT), {"ebsEncryptionByDefault": enabled}


def iam_root_keys(clients, account_id: str, locator=None) -> State:
    present = clients["iam"].get_account_summary()["SummaryMap"].get("AccountAccessKeysPresent", 0)
    return (COMPLIANT if present == 0 else NONCOMPLIANT), {"accountAccessKeysPresent": present}


VERIFIERS = {
    "S3.1": s3_account_bpa,
    "S3.8": s3_bucket_bpa,
    "EC2.2": ec2_default_sg,
    "EC2.7": ec2_ebs_default,
    "IAM.4": iam_root_keys,
}


def verify(control: str, clients, account_id: str, locator) -> State:
    fn = VERIFIERS.get(control)
    if not fn:
        return UNKNOWN, {"error": f"sem verificador para {control}"}
    try:
        return fn(clients, account_id, locator)
    except ClientError as err:
        return UNKNOWN, {"error": f"{_code(err)}: {err.response.get('Error', {}).get('Message')}"}


def resource_tags(control: str, clients, locator) -> Dict[str, str]:
    """Tags do recurso, para o mapa de exceções. Controles de conta não têm tags."""
    try:
        if control == "S3.8":
            tagset = clients["s3"].get_bucket_tagging(Bucket=locator).get("TagSet", [])
            return {t["Key"]: t["Value"] for t in tagset}
        if control == "EC2.2":
            group = clients["ec2"].describe_security_groups(GroupIds=[locator])["SecurityGroups"][0]
            return {t["Key"]: t["Value"] for t in group.get("Tags", [])}
    except ClientError:
        return {}
    return {}

import argparse
import json
import os
from typing import Any, Dict, List, Optional, Tuple

import yaml

from lib.aws_clients import get_client
from lib.io_utils import ensure_directory, utc_timestamp


# =============================================================================
# Helpers: target extraction
# =============================================================================

def _lower(s: Optional[str]) -> str:
    return (s or "").lower()


def extract_bucket_from_arn_or_id(resource_id: str) -> Optional[str]:
    """
    Accepts:
      - arn:aws:s3:::bucket-name
      - bucket-name
      - s3://bucket-name
    Returns:
      - bucket-name or None
    """
    if not resource_id:
        return None

    rid = resource_id.strip()

    if "arn:aws:s3:::" in rid:
        return rid.split(":::")[-1].strip()

    if rid.startswith("s3://"):
        return rid.replace("s3://", "").strip("/")

    # basic bucket-name heuristic
    if "://" not in rid and "/" not in rid and ":" not in rid and len(rid) >= 3:
        return rid

    return None


def find_s3_bucket_target(resources: List[Dict[str, Any]]) -> Optional[str]:
    for r in resources:
        r_type = _lower(r.get("type"))
        r_id = r.get("id") or ""
        if "s3" in r_type and "bucket" in r_type:
            b = extract_bucket_from_arn_or_id(r_id)
            if b:
                return b

    # fallback: try any id
    for r in resources:
        b = extract_bucket_from_arn_or_id(r.get("id") or "")
        if b:
            return b

    return None


def find_security_group_target(resources: List[Dict[str, Any]]) -> Optional[str]:
    """
    Return a security group id if found (sg-xxxx).
    Security Hub may return:
      - id: sg-xxxx
      - id: arn:aws:ec2:region:acct:security-group/sg-xxxx
    """
    for r in resources:
        rid = (r.get("id") or "").strip()
        if rid.startswith("sg-"):
            return rid
        if "security-group/sg-" in rid:
            return rid.split("security-group/")[-1]
    return None


# =============================================================================
# Heuristic inference (best-effort)
# =============================================================================

def build_finding_blob(item: Dict[str, Any]) -> str:
    """
    Build a text blob from normalized + raw finding for safe inference.
    """
    f = item.get("finding", {}) or {}
    norm = f.get("normalized", {}) or {}
    raw = f.get("raw", {}) or {}

    parts = []
    for k in ("title", "generatorId"):
        v = norm.get(k)
        if v:
            parts.append(str(v))
    for k in ("Title", "GeneratorId", "Description"):
        v = raw.get(k)
        if v:
            parts.append(str(v))

    for t in (norm.get("types") or raw.get("Types") or []):
        parts.append(str(t))

    pf = raw.get("ProductFields") or {}
    for k in ("ControlId", "RuleId", "StandardsArn", "StandardsSubscriptionArn"):
        if pf.get(k):
            parts.append(str(pf.get(k)))

    return " | ".join(parts).lower()


def infer_action_if_possible(item: Dict[str, Any]) -> Tuple[str, Dict[str, Any], str]:
    """
    Returns (action_name, params, reason).

    If cannot infer safely, returns ("manual", {}, "...").

    IMPORTANT: best-effort inference should be used carefully and ideally in dry-run first.
    """
    blob = build_finding_blob(item)
    f = item.get("finding", {}) or {}
    norm = f.get("normalized", {}) or {}
    resources = norm.get("resources", []) or []

    # S3 public exposure
    if find_s3_bucket_target(resources) and ("public" in blob or "block public access" in blob):
        return "s3_public_access_block", {}, "Best-effort inference: S3 public exposure keywords detected"

    # SG world-open exposure
    if find_security_group_target(resources) and ("0.0.0.0/0" in blob or "::/0" in blob or "world" in blob):
        return "sg_remove_world_open_ports", {"ports": [22, 3389]}, "Best-effort inference: SG world-open keywords detected"

    # EBS encryption by default
    if "ebs" in blob and "encryption by default" in blob:
        return "enable_ebs_encryption_by_default", {}, "Best-effort inference: EBS encryption-by-default keyword detected"

    # S3 encryption baseline
    if find_s3_bucket_target(resources) and ("encryption" in blob and ("s3" in blob or "bucket" in blob)):
        return "s3_enable_default_encryption", {}, "Best-effort inference: S3 encryption keyword detected"

    # S3 versioning baseline
    if find_s3_bucket_target(resources) and ("versioning" in blob and ("s3" in blob or "bucket" in blob)):
        return "s3_enable_versioning", {}, "Best-effort inference: S3 versioning keyword detected"

    # S3 SSL-only (conservative inference)
    if find_s3_bucket_target(resources) and ("insecure transport" in blob or "securetransport" in blob or "ssl" in blob or "tls" in blob):
        return "s3_enforce_ssl_only_policy", {}, "Best-effort inference: S3 SSL/TLS enforcement keywords detected"

    return "manual", {}, "Best-effort inference: no safe action inferred"


# =============================================================================
# Remediation handlers
# =============================================================================

def remediate_s3_public_access_block(s3, bucket: str, dry_run: bool) -> Tuple[bool, str]:
    if dry_run:
        return True, f"DRY-RUN: would enable S3 Public Access Block on bucket {bucket}"

    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    return True, f"OK: enabled S3 Public Access Block on bucket {bucket}"


def remediate_s3_enable_default_encryption(s3, bucket: str, dry_run: bool) -> Tuple[bool, str]:
    """
    Enables default encryption (SSE-S3/AES256).
    Safe baseline for most orgs.
    """
    if dry_run:
        return True, f"DRY-RUN: would enable default encryption (SSE-S3) on bucket {bucket}"

    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
                    "BucketKeyEnabled": True,
                }
            ]
        },
    )
    return True, f"OK: enabled default encryption (SSE-S3) on bucket {bucket}"


def remediate_s3_enable_versioning(s3, bucket: str, dry_run: bool) -> Tuple[bool, str]:
    if dry_run:
        return True, f"DRY-RUN: would enable versioning on bucket {bucket}"

    s3.put_bucket_versioning(
        Bucket=bucket,
        VersioningConfiguration={"Status": "Enabled"},
    )
    return True, f"OK: enabled versioning on bucket {bucket}"


SSL_ONLY_SID = "DenyInsecureTransport"


def remediate_s3_enforce_ssl_only_policy(s3, bucket: str, dry_run: bool) -> Tuple[bool, str]:
    """
    Ensures the bucket policy denies any request where aws:SecureTransport == false (HTTPS-only).
    This appends a Deny statement without removing existing statements.

    NOTE: Validate legacy HTTP clients before applying in production.
    """
    policy_doc = {"Version": "2012-10-17", "Statement": []}

    try:
        resp = s3.get_bucket_policy(Bucket=bucket)
        policy_doc = json.loads(resp["Policy"])
    except s3.exceptions.NoSuchBucketPolicy:
        pass

    if "Statement" not in policy_doc or not isinstance(policy_doc["Statement"], list):
        policy_doc["Statement"] = []

    # already enforced?
    for stmt in policy_doc["Statement"]:
        if stmt.get("Sid") == SSL_ONLY_SID:
            if dry_run:
                return True, f"DRY-RUN: SSL-only policy already present on bucket {bucket}"
            return True, f"NOOP: SSL-only policy already present on bucket {bucket}"

    deny_stmt = {
        "Sid": SSL_ONLY_SID,
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [
            f"arn:aws:s3:::{bucket}",
            f"arn:aws:s3:::{bucket}/*",
        ],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    }

    policy_doc["Statement"].append(deny_stmt)

    if dry_run:
        return True, f"DRY-RUN: would enforce SSL-only policy on {bucket}: {json.dumps(policy_doc)}"

    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy_doc))
    return True, f"OK: enforced SSL-only policy on bucket {bucket}"


def remediate_enable_ebs_encryption_by_default(ec2, dry_run: bool) -> Tuple[bool, str]:
    if dry_run:
        return True, "DRY-RUN: would enable EBS Encryption by Default for this region"

    ec2.enable_ebs_encryption_by_default()
    return True, "OK: enabled EBS Encryption by Default for this region"


def remediate_sg_remove_world_open_ports(ec2, sg_id: str, ports: Optional[List[int]], dry_run: bool) -> Tuple[bool, str]:
    """
    Removes inbound rules open to the world for specified ports.
    Also removes IPv6 ::/0 if found.
    If ports is None or empty, removes ALL ports/ranges that are open to world (0.0.0.0/0 or ::/0).
    """
    desc = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    ip_permissions = desc.get("IpPermissions", []) or []

    def port_in_scope(from_p: Optional[int], to_p: Optional[int]) -> bool:
        if not ports:
            return True
        if from_p is None or to_p is None:
            return False
        return any(from_p <= p <= to_p for p in ports)

    to_revoke: List[Dict[str, Any]] = []

    for perm in ip_permissions:
        proto = perm.get("IpProtocol")
        from_p = perm.get("FromPort")
        to_p = perm.get("ToPort")

        if ports and proto not in ("tcp", "udp"):
            continue

        if not port_in_scope(from_p, to_p):
            continue

        ipv4_bad = [r for r in (perm.get("IpRanges") or []) if r.get("CidrIp") == "0.0.0.0/0"]
        ipv6_bad = [r for r in (perm.get("Ipv6Ranges") or []) if r.get("CidrIpv6") == "::/0"]

        if ipv4_bad or ipv6_bad:
            revoke_perm: Dict[str, Any] = {"IpProtocol": proto}
            if from_p is not None:
                revoke_perm["FromPort"] = from_p
            if to_p is not None:
                revoke_perm["ToPort"] = to_p
            if ipv4_bad:
                revoke_perm["IpRanges"] = ipv4_bad
            if ipv6_bad:
                revoke_perm["Ipv6Ranges"] = ipv6_bad
            to_revoke.append(revoke_perm)

    if not to_revoke:
        return True, f"NOOP: no world-open inbound rules matched on {sg_id}"

    if dry_run:
        return True, f"DRY-RUN: would revoke {len(to_revoke)} inbound permission(s) from {sg_id}: {to_revoke}"

    ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=to_revoke)
    return True, f"OK: revoked {len(to_revoke)} world-open inbound permission(s) from {sg_id}"


# =============================================================================
# Action dispatcher
# =============================================================================

def execute_action(
    action_name: str,
    params: Dict[str, Any],
    item: Dict[str, Any],
    clients: Dict[str, Any],
    dry_run: bool
) -> Tuple[bool, str]:
    finding_norm = ((item.get("finding") or {}).get("normalized") or {})
    resources = finding_norm.get("resources", []) or []

    # ---- S3 actions ----
    if action_name == "s3_public_access_block":
        bucket = params.get("bucket") or find_s3_bucket_target(resources)
        if not bucket:
            return False, "Could not determine S3 bucket target"
        return remediate_s3_public_access_block(clients["s3"], bucket, dry_run)

    if action_name == "s3_enable_default_encryption":
        bucket = params.get("bucket") or find_s3_bucket_target(resources)
        if not bucket:
            return False, "Could not determine S3 bucket target"
        return remediate_s3_enable_default_encryption(clients["s3"], bucket, dry_run)

    if action_name == "s3_enable_versioning":
        bucket = params.get("bucket") or find_s3_bucket_target(resources)
        if not bucket:
            return False, "Could not determine S3 bucket target"
        return remediate_s3_enable_versioning(clients["s3"], bucket, dry_run)

    if action_name == "s3_enforce_ssl_only_policy":
        bucket = params.get("bucket") or find_s3_bucket_target(resources)
        if not bucket:
            return False, "Could not determine S3 bucket target"
        return remediate_s3_enforce_ssl_only_policy(clients["s3"], bucket, dry_run)

    # ---- EC2 / EBS actions ----
    if action_name == "enable_ebs_encryption_by_default":
        return remediate_enable_ebs_encryption_by_default(clients["ec2"], dry_run)

    if action_name == "sg_remove_world_open_ports":
        sg_id = params.get("security_group_id") or find_security_group_target(resources)
        if not sg_id:
            return False, "Could not determine Security Group target"
        ports = params.get("ports")
        return remediate_sg_remove_world_open_ports(clients["ec2"], sg_id, ports, dry_run)

    return False, f"UNSUPPORTED_ACTION: {action_name}"


# =============================================================================
# Main
# =============================================================================

def main():
    ap = argparse.ArgumentParser(
        description="Security Hub Control Plane - Execute remediations from the YAML control artifact"
    )
    ap.add_argument("--region", required=True)
    ap.add_argument("--profile", default=None)
    ap.add_argument("--yaml", required=True, help="Path to the YAML control artifact generated by previous steps")
    ap.add_argument("--mode", choices=["dry-run", "apply"], default="dry-run")
    ap.add_argument(
        "--best-effort",
        action="store_true",
        help="Attempt to infer and execute safe remediations even for MANUAL items (use dry-run first)"
    )
    ap.add_argument("--output-dir", default="outputs")
    args = ap.parse_args()

    dry_run = args.mode == "dry-run"

    with open(args.yaml, "r", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}

    clients = {
        "s3": get_client("s3", region=args.region, profile=args.profile),
        "ec2": get_client("ec2", region=args.region, profile=args.profile),
    }

    executed_at = utc_timestamp()
    results = {
        "apiVersion": "shcp/v1",
        "kind": "RemediationResults",
        "metadata": {
            "executedAt": executed_at,
            "region": args.region,
            "mode": args.mode,
            "bestEffort": args.best_effort,
            "sourceYaml": args.yaml,
        },
        "spec": {
            "summary": {
                "total": 0,
                "executed": 0,
                "succeeded": 0,
                "failed": 0,
                "manual_required": 0,
                "ignored": 0,
                "unsupported": 0,
                "not_executed": 0,
                "best_effort_executed": 0,
            },
            "results": [],
        },
    }

    items = ((doc.get("spec") or {}).get("items") or [])
    results["spec"]["summary"]["total"] = len(items)

    for item in items:
        decision = item.get("decision", {}) or {}
        decision_type = decision.get("type", "MANUAL")

        action = item.get("action", {}) or {}
        action_name = action.get("name", "manual")
        action_params = action.get("params", {}) or {}

        finding_norm = ((item.get("finding") or {}).get("normalized") or {})

        ok = False
        msg = "MANUAL_REQUIRED"
        executed = False
        inferred = False
        inference_reason = None

        # Determine execution based on decision and best-effort
        if decision_type == "IGNORE":
            msg = "IGNORED"
            results["spec"]["summary"]["ignored"] += 1

        else:
            if decision_type == "AUTO" and action_name != "manual":
                executed = True
            elif args.best_effort and decision_type == "MANUAL":
                inferred_action, inferred_params, reason = infer_action_if_possible(item)
                if inferred_action != "manual":
                    inferred = True
                    inference_reason = reason
                    action_name = inferred_action
                    action_params = inferred_params
                    executed = True

            if executed:
                results["spec"]["summary"]["executed"] += 1
                if inferred:
                    results["spec"]["summary"]["best_effort_executed"] += 1

                try:
                    ok, msg = execute_action(action_name, action_params, item, clients, dry_run)
                except Exception as e:
                    ok, msg = False, f"ERROR: {type(e).__name__}: {e}"

                if msg.startswith("UNSUPPORTED_ACTION"):
                    results["spec"]["summary"]["unsupported"] += 1

                if ok:
                    results["spec"]["summary"]["succeeded"] += 1
                else:
                    if not msg.startswith("UNSUPPORTED_ACTION"):
                        results["spec"]["summary"]["failed"] += 1

            else:
                if decision_type == "MANUAL":
                    msg = "MANUAL_REQUIRED"
                    results["spec"]["summary"]["manual_required"] += 1
                else:
                    msg = f"NOT_EXECUTED (decision={decision_type}, action={action_name})"
                    results["spec"]["summary"]["not_executed"] += 1

        results["spec"]["results"].append({
            "itemId": item.get("id"),
            "findingId": finding_norm.get("findingId"),
            "title": finding_norm.get("title"),
            "decision": decision_type,
            "finalAction": action_name,
            "finalParams": action_params,
            "executed": executed,
            "inferred": inferred,
            "inferenceReason": inference_reason,
            "ok": ok,
            "message": msg,
        })

    out_dir = os.path.join(args.output_dir, executed_at)
    ensure_directory(out_dir)

    out_path = os.path.join(out_dir, "remediation_results.yaml")
    with open(out_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(results, f, sort_keys=False, allow_unicode=True)

    s = results["spec"]["summary"]
    print(f"[OK] Results written: {out_path}")
    print(f" - total: {s['total']}")
    print(f" - executed: {s['executed']} (best-effort: {s['best_effort_executed']})")
    print(f" - succeeded: {s['succeeded']}")
    print(f" - failed: {s['failed']}")
    print(f" - manual_required: {s['manual_required']}")
    print(f" - ignored: {s['ignored']}")
    print(f" - unsupported: {s['unsupported']}")


if __name__ == "__main__":
    main()

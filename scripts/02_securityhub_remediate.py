import argparse
import json
from typing import Any, Dict, List, Optional, Tuple

from lib.aws_clients import client
from lib.io_utils import ensure_dir, utc_ts, write_json


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# -----------------------
# Remediações (exemplos)
# -----------------------

def remediate_s3_public_access_block(s3c, bucket_name: str, dry_run: bool) -> Tuple[bool, str]:
    """Aplica PublicAccessBlock completo."""
    if dry_run:
        return True, f"DRY-RUN: aplicaria PublicAccessBlock em {bucket_name}"
    s3c.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    return True, f"OK: PublicAccessBlock aplicado em {bucket_name}"


def remediate_sg_remove_0_0_0_0_0(ec2, sg_id: str, ports: List[int], dry_run: bool) -> Tuple[bool, str]:
    """
    Remove regras IPv4 0.0.0.0/0 para portas específicas (inbound).
    Obs.: exige descrever SG e revogar apenas as perms que batem.
    """
    desc = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    ip_perms = desc.get("IpPermissions", [])
    to_revoke = []

    for p in ip_perms:
        from_p = p.get("FromPort")
        to_p = p.get("ToPort")
        ip_ranges = p.get("IpRanges", [])
        if not ip_ranges:
            continue
        if from_p is None or to_p is None:
            continue
        # Se range inclui alguma porta alvo
        if any(port >= from_p and port <= to_p for port in ports):
            # filtra apenas 0.0.0.0/0
            bad_ranges = [r for r in ip_ranges if r.get("CidrIp") == "0.0.0.0/0"]
            if bad_ranges:
                to_revoke.append({
                    "IpProtocol": p.get("IpProtocol"),
                    "FromPort": from_p,
                    "ToPort": to_p,
                    "IpRanges": bad_ranges,
                })

    if not to_revoke:
        return True, f"NOOP: nenhuma regra 0.0.0.0/0 nas portas {ports} em {sg_id}"

    if dry_run:
        return True, f"DRY-RUN: revogaria {len(to_revoke)} perms em {sg_id}: {to_revoke}"

    ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=to_revoke)
    return True, f"OK: regras 0.0.0.0/0 removidas em {sg_id} (ports={ports})"


def remediate_ebs_encryption_by_default(ec2, dry_run: bool) -> Tuple[bool, str]:
    if dry_run:
        return True, "DRY-RUN: habilitaria EBS Encryption by Default"
    ec2.enable_ebs_encryption_by_default()
    return True, "OK: EBS Encryption by Default habilitado"


# -----------------------
# Utilitários
# -----------------------

def extract_bucket_from_resource(resource_id: str) -> Optional[str]:
    # Ex.: arn:aws:s3:::my-bucket
    if resource_id.startswith("arn:aws:s3:::"):
        return resource_id.split(":::")[1]
    return None


def is_sg_id(s: str) -> bool:
    return s.startswith("sg-")


def main():
    ap = argparse.ArgumentParser(description="Security Hub Control Plane - Remediate (execute plan)")
    ap.add_argument("--region", required=True)
    ap.add_argument("--profile", default=None)

    ap.add_argument("--plan", required=True, help="outputs/<ts>/plan.json")
    ap.add_argument("--outdir", default="outputs")
    ap.add_argument("--dry-run", action="store_true", help="Não aplica mudanças")
    ap.add_argument("--annotate-findings", action="store_true", help="Opcional: atualizar workflow/note no Security Hub")
    args = ap.parse_args()

    plan = load_json(args.plan)
    actions = plan.get("actions", [])

    sh = client("securityhub", region=args.region, profile=args.profile)
    s3c = client("s3", region=args.region, profile=args.profile)
    ec2 = client("ec2", region=args.region, profile=args.profile)

    run_ts = utc_ts()
    run_dir = f"{args.outdir}/{run_ts}"
    ensure_dir(run_dir)

    results: List[Dict[str, Any]] = []

    for a in actions:
        action_name = a.get("proposed_action")
        params = a.get("action_params", {})
        resources = a.get("resources", [])
        finding_id = a.get("finding_id")

        ok = False
        msg = "UNHANDLED"

        try:
            if action_name == "s3_public_access_block":
                # pega o primeiro bucket possível
                bucket = None
                for rid in resources:
                    bucket = extract_bucket_from_resource(rid)
                    if bucket:
                        break
                if not bucket and params.get("bucket"):
                    bucket = params["bucket"]
                if not bucket:
                    ok, msg = False, "Não foi possível determinar o bucket"
                else:
                    ok, msg = remediate_s3_public_access_block(s3c, bucket, args.dry_run)

            elif action_name == "sg_remove_world_open_ports":
                ports = params.get("ports", [22, 3389])
                # pega sg- do resources
                sg = None
                for rid in resources:
                    if is_sg_id(rid):
                        sg = rid
                        break
                if not sg and params.get("security_group_id"):
                    sg = params["security_group_id"]
                if not sg:
                    ok, msg = False, "Não foi possível determinar o Security Group"
                else:
                    ok, msg = remediate_sg_remove_0_0_0_0_0(ec2, sg, ports, args.dry_run)

            elif action_name == "enable_ebs_encryption_by_default":
                ok, msg = remediate_ebs_encryption_by_default(ec2, args.dry_run)

            else:
                ok, msg = False, f"Ação não suportada: {action_name}"

        except Exception as e:
            ok, msg = False, f"ERROR: {type(e).__name__}: {e}"

        results.append({
            "finding_id": finding_id,
            "action": action_name,
            "dry_run": args.dry_run,
            "ok": ok,
            "message": msg,
            "resources": resources,
        })

        # Opcional: anotar findings no Security Hub para fechar o loop (Control Plane)
        if args.annotate_findings and finding_id:
            try:
                note = {"Text": f"Remediation result: ok={ok} msg={msg}", "UpdatedBy": "securityhub-control-plane"}
                sh.batch_update_findings(
                    FindingIdentifiers=[{"Id": finding_id, "ProductArn": a.get("product_arn", "")} ] if a.get("product_arn") else [],
                    # Se você não tiver ProductArn no plano, prefira não forçar.
                )
            except Exception:
                # Mantém o fluxo. Anotação é best-effort.
                pass

    out_path = f"{run_dir}/remediate_results.json"
    write_json(out_path, {"plan": args.plan, "results": results})
    print(f"[OK] Remediate finalizado: {out_path}")
    print(f" - ações: {len(results)} | sucesso: {sum(1 for r in results if r['ok'])}")


if __name__ == "__main__":
    main()

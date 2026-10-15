"""EC2.2: remove todas as regras de entrada e saída do security group default da VPC.

Só atua em SG chamado "default": qualquer outro grupo é recusado.
"""


def _strip(permission):
    # A API de revoke não aceita os campos que o describe devolve só para leitura.
    clean = {k: v for k, v in permission.items() if k in ("IpProtocol", "FromPort", "ToPort", "IpRanges",
                                                          "Ipv6Ranges", "PrefixListIds", "UserIdGroupPairs")}
    clean["UserIdGroupPairs"] = [{k: v for k, v in pair.items() if k in ("GroupId", "UserId", "VpcId")}
                                 for pair in clean.get("UserIdGroupPairs", [])]
    return {k: v for k, v in clean.items() if v not in ([], None)}


def run(clients, ctx, dry_run):
    sg_id = ctx["locator"]
    group = clients["ec2"].describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    if group.get("GroupName") != "default":
        return {"ok": False, "message": f"REFUSED: {sg_id} não é o security group default", "changes": []}

    ingress = [_strip(p) for p in group.get("IpPermissions", [])]
    egress = [_strip(p) for p in group.get("IpPermissionsEgress", [])]
    changes = []
    if ingress:
        changes.append({"api": "ec2:RevokeSecurityGroupIngress", "GroupId": sg_id, "rules": len(ingress)})
    if egress:
        changes.append({"api": "ec2:RevokeSecurityGroupEgress", "GroupId": sg_id, "rules": len(egress)})
    if not changes:
        return {"ok": True, "message": f"NOOP: {sg_id} já está sem regras", "changes": []}
    if dry_run:
        return {"ok": True, "changes": changes,
                "message": f"DRY-RUN: removeria {len(ingress)} regra(s) de entrada e {len(egress)} de saída de {sg_id}"}

    if ingress:
        clients["ec2"].revoke_security_group_ingress(GroupId=sg_id, IpPermissions=ingress)
    if egress:
        clients["ec2"].revoke_security_group_egress(GroupId=sg_id, IpPermissions=egress)
    return {"ok": True, "changes": changes,
            "message": f"OK: {len(ingress)} regra(s) de entrada e {len(egress)} de saída removidas de {sg_id}"}

"""EC2.7: liga a criptografia de EBS por padrão na região do cliente."""


def run(clients, ctx, dry_run):
    change = {"api": "ec2:EnableEbsEncryptionByDefault", "Region": ctx.get("region")}
    if dry_run:
        return {"ok": True, "message": "DRY-RUN: ligaria a criptografia de EBS por padrão", "changes": [change]}
    clients["ec2"].enable_ebs_encryption_by_default()
    return {"ok": True, "message": "OK: criptografia de EBS por padrão ligada", "changes": [change]}

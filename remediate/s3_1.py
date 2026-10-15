"""S3.1: liga as quatro flags do S3 Block Public Access na conta."""

from scanner.resources import BPA_KEYS


def run(clients, ctx, dry_run):
    config = {k: True for k in BPA_KEYS}
    change = {"api": "s3control:PutPublicAccessBlock", "AccountId": ctx["account_id"]}
    if dry_run:
        return {"ok": True, "message": "DRY-RUN: ligaria o Block Public Access da conta", "changes": [change]}
    clients["s3control"].put_public_access_block(AccountId=ctx["account_id"], PublicAccessBlockConfiguration=config)
    return {"ok": True, "message": "OK: Block Public Access da conta ligado", "changes": [change]}

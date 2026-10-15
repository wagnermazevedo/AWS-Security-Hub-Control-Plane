"""S3.8: liga as quatro flags do S3 Block Public Access no bucket."""

from scanner.resources import BPA_KEYS


def run(clients, ctx, dry_run):
    bucket = ctx["locator"]
    config = {k: True for k in BPA_KEYS}
    change = {"api": "s3:PutPublicAccessBlock", "Bucket": bucket}
    if dry_run:
        return {"ok": True, "message": f"DRY-RUN: ligaria o Block Public Access do bucket {bucket}", "changes": [change]}
    clients["s3"].put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=config)
    return {"ok": True, "message": f"OK: Block Public Access do bucket {bucket} ligado", "changes": [change]}

"""Ações de remediação: uma função pequena por controle.

Toda ação recebe (clients, ctx, dry_run) e devolve um dict com ok, message e
changes. ctx traz account_id e locator (nome do bucket, sg-...). Em dry-run
nenhuma API de escrita é chamada.
"""

from remediate.ec2_2 import run as ec2_default_sg_revoke_all
from remediate.ec2_7 import run as ec2_ebs_encryption_by_default
from remediate.s3_1 import run as s3_account_public_access_block
from remediate.s3_8 import run as s3_bucket_public_access_block

REGISTRY = {
    "s3_account_public_access_block": s3_account_public_access_block,
    "s3_bucket_public_access_block": s3_bucket_public_access_block,
    "ec2_default_sg_revoke_all": ec2_default_sg_revoke_all,
    "ec2_ebs_encryption_by_default": ec2_ebs_encryption_by_default,
}

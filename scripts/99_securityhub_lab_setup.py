#!/usr/bin/env python3
"""[99] LAB SETUP: cria o ambiente que os scripts 00, 01 e 02 vão testar. Use SOMENTE numa conta de testes.

O que o setup faz:
  1. liga o AWS Config, o Security Hub e o padrão FSBP (se ainda não estiverem ligados);
  2. desliga duas proteções de conta: S3 Block Public Access (S3.1) e criptografia de EBS por padrão (EC2.7),
     guardando o estado anterior em lab_insecure/.account_state.json;
  3. sobe o lab_insecure/insecure-stack.yaml: dois buckets sem Block Public Access (S3.8, um deles com
     exceção documentada) e uma VPC com SSH aberto no security group default (EC2.2).

  python3 scripts/99_securityhub_lab_setup.py --region us-east-1            # cria
  python3 scripts/99_securityhub_lab_setup.py --region us-east-1 --destroy  # desfaz e restaura a conta
"""

import argparse
import json
import os

import _bootstrap  # noqa: F401
from botocore.exceptions import ClientError

from lib.aws import client, session
from lib.io import repo_path
from scanner.resources import BPA_KEYS

STATE_FILE = repo_path("lab_insecure", ".account_state.json")
TEMPLATE = repo_path("lab_insecure", "insecure-stack.yaml")


def _code(err):
    return err.response.get("Error", {}).get("Code", "")


def enable_config(c, account_id, region):
    if c["config"].describe_configuration_recorders().get("ConfigurationRecorders"):
        name = c["config"].describe_configuration_recorders()["ConfigurationRecorders"][0]["name"]
    else:
        bucket = f"shcp-config-{account_id}-{region}"
        kwargs = {} if region == "us-east-1" else {"CreateBucketConfiguration": {"LocationConstraint": region}}
        try:
            c["s3"].create_bucket(Bucket=bucket, **kwargs)
        except ClientError as err:
            if _code(err) != "BucketAlreadyOwnedByYou":
                raise
        c["s3"].put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={k: True for k in BPA_KEYS})
        c["s3"].put_bucket_policy(Bucket=bucket, Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "ConfigAclCheck", "Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"},
                 "Action": ["s3:GetBucketAcl", "s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket}",
                 "Condition": {"StringEquals": {"AWS:SourceAccount": account_id}}},
                {"Sid": "ConfigWrite", "Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"},
                 "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/Config/*",
                 "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control",
                                                "AWS:SourceAccount": account_id}}},
            ]}))
        try:
            c["iam"].create_service_linked_role(AWSServiceName="config.amazonaws.com")
        except ClientError as err:
            if _code(err) != "InvalidInput":  # já existe
                raise
        name = "default"
        c["config"].put_configuration_recorder(ConfigurationRecorder={
            "name": name,
            "roleARN": f"arn:aws:iam::{account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
            "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True},
        })
        c["config"].put_delivery_channel(DeliveryChannel={"name": "default", "s3BucketName": bucket})
        print(f"[OK] AWS Config configurado (bucket {bucket})")
    c["config"].start_configuration_recorder(ConfigurationRecorderName=name)
    print("[OK] AWS Config gravando")


def enable_securityhub(c, region):
    try:
        c["securityhub"].enable_security_hub(EnableDefaultStandards=False, ControlFindingGenerator="SECURITY_CONTROL")
        print("[OK] Security Hub ligado")
    except ClientError as err:
        if _code(err) != "ResourceConflictException":
            raise
        print("[OK] Security Hub já estava ligado")
    fsbp = f"arn:aws:securityhub:{region}::standards/aws-foundational-security-best-practices/v/1.0.0"
    c["securityhub"].batch_enable_standards(StandardsSubscriptionRequests=[{"StandardsArn": fsbp}])
    print("[OK] Padrão FSBP habilitado (a primeira avaliação pode levar horas)")


def save_account_state(c, account_id):
    if os.path.exists(STATE_FILE):
        return  # preserva o estado original de antes do primeiro setup
    try:
        bpa = c["s3control"].get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"]
    except ClientError as err:
        if _code(err) != "NoSuchPublicAccessBlockConfiguration":
            raise
        bpa = None
    ebs = c["ec2"].get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump({"accountPublicAccessBlock": bpa, "ebsEncryptionByDefault": ebs}, f, indent=2)


def setup(c, account_id, region, stack, with_securityhub):
    if with_securityhub:
        enable_config(c, account_id, region)
        enable_securityhub(c, region)

    save_account_state(c, account_id)
    try:
        c["s3control"].delete_public_access_block(AccountId=account_id)
    except ClientError as err:
        if _code(err) != "NoSuchPublicAccessBlockConfiguration":
            raise
    c["ec2"].disable_ebs_encryption_by_default()
    print("[OK] S3.1 e EC2.7: Block Public Access da conta e criptografia de EBS por padrão desligados")

    with open(TEMPLATE, "r", encoding="utf-8") as f:
        body = f.read()
    try:
        c["cloudformation"].create_stack(StackName=stack, TemplateBody=body, Tags=[{"Key": "Environment", "Value": "lab"}])
        c["cloudformation"].get_waiter("stack_create_complete").wait(StackName=stack)
    except ClientError as err:
        if _code(err) != "AlreadyExistsException":
            raise
        print(f"[OK] Stack {stack} já existia")
    outputs = c["cloudformation"].describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])
    for out in outputs:
        print(f"   {out['OutputKey']:<26} {out['OutputValue']}")
    print("[OK] Laboratório pronto. S3.8 e EC2.2 são reavaliados em minutos; S3.1 e EC2.7 podem levar horas.")


def destroy(c, account_id, stack):
    c["cloudformation"].delete_stack(StackName=stack)
    c["cloudformation"].get_waiter("stack_delete_complete").wait(StackName=stack)
    print(f"[OK] Stack {stack} removida")

    if not os.path.exists(STATE_FILE):
        print("[WARN] Sem estado salvo: confira o Block Public Access da conta e a criptografia de EBS")
        return
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        state = json.load(f)
    if state.get("accountPublicAccessBlock"):
        c["s3control"].put_public_access_block(AccountId=account_id,
                                               PublicAccessBlockConfiguration=state["accountPublicAccessBlock"])
        print("[OK] Block Public Access da conta restaurado")
    if state.get("ebsEncryptionByDefault"):
        c["ec2"].enable_ebs_encryption_by_default()
        print("[OK] Criptografia de EBS por padrão restaurada")
    os.remove(STATE_FILE)
    print("O Security Hub e o AWS Config continuam ligados; desligue-os se a conta for só de laboratório.")


def main():
    parser = argparse.ArgumentParser(description="Security Hub Lab Setup (conta de testes)")
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile", default=None)
    parser.add_argument("--stack-name", default="shcp-insecure-lab")
    parser.add_argument("--destroy", action="store_true", help="Remove o laboratório e restaura a conta")
    parser.add_argument("--skip-securityhub", action="store_true", help="Não liga Config/Security Hub/FSBP")
    parser.add_argument("--yes", action="store_true", help="Não pede confirmação")
    args = parser.parse_args()

    sess = session(args.profile, args.region)
    c = {svc: client(sess, svc) for svc in ("sts", "s3", "s3control", "ec2", "iam", "config", "securityhub", "cloudformation")}
    account_id = c["sts"].get_caller_identity()["Account"]

    if args.destroy:
        destroy(c, account_id, args.stack_name)
        return

    print(f"Conta {account_id} · região {args.region}")
    print("Este setup desliga proteções da conta e cria recursos inseguros de propósito.")
    if not args.yes and input("Digite LAB para confirmar que esta é uma conta de testes: ").strip() != "LAB":
        raise SystemExit("Cancelado.")
    setup(c, account_id, args.region, args.stack_name, not args.skip_securityhub)


if __name__ == "__main__":
    main()

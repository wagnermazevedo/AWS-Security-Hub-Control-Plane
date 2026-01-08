import argparse
import random
import string

from lib.aws_clients import client


def rand_suffix(n=8):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def main():
    ap = argparse.ArgumentParser(description="Lab insecure resources for Security Hub validation")
    ap.add_argument("--region", required=True)
    ap.add_argument("--profile", default=None)
    ap.add_argument("--create-s3", action="store_true")
    ap.add_argument("--create-sg", action="store_true")
    ap.add_argument("--vpc-id", default=None, help="Obrigatório se --create-sg")
    args = ap.parse_args()

    s3c = client("s3", region=args.region, profile=args.profile)
    ec2 = client("ec2", region=args.region, profile=args.profile)

    if args.create_s3:
        bucket = f"lab-insecure-shcp-{rand_suffix()}"
        # create_bucket difere em us-east-1
        if args.region == "us-east-1":
            s3c.create_bucket(Bucket=bucket)
        else:
            s3c.create_bucket(
                Bucket=bucket,
                CreateBucketConfiguration={"LocationConstraint": args.region},
            )
        # NÃO aplica PublicAccessBlock (inseguro)
        print(f"[OK] Bucket criado (inseguro): {bucket}")

    if args.create_sg:
        if not args.vpc_id:
            raise SystemExit("--vpc-id é obrigatório para criar SG")
        sg = ec2.create_security_group(
            GroupName=f"lab-insecure-sg-{rand_suffix()}",
            Description="Insecure SG for Security Hub findings",
            VpcId=args.vpc_id,
        )["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "INSECURE SSH"}],
                }
            ],
        )
        print(f"[OK] SG criado (inseguro): {sg} (SSH aberto 0.0.0.0/0)")


if __name__ == "__main__":
    main()

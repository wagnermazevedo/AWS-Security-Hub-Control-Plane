import argparse
import random
import string
from lib.aws_clients import get_client


def random_suffix(size=6):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(size))


def main():
    parser = argparse.ArgumentParser(
        description="Create insecure/non-compliant AWS resources for Security Hub & Governance testing"
    )
    parser.add_argument("--region", required=True)
    parser.add_argument("--create-s3", action="store_true", help="Create an unencrypted, public-ready S3 bucket without tags")
    parser.add_argument("--create-sg", action="store_true", help="Create a world-open Security Group (Port 22)")
    parser.add_argument("--create-ebs", action="store_true", help="Create an unencrypted EBS volume")
    parser.add_argument("--vpc-id", help="Required for Security Group creation")

    args = parser.parse_args()

    s3 = get_client("s3", region=args.region)
    ec2 = get_client("ec2", region=args.region)

    # 1. S3 Bucket sem criptografia, sem versionamento e sem tags
    if args.create_s3:
        bucket_name = f"insecure-shcp-{random_suffix()}"
        s3.create_bucket(Bucket=bucket_name)
        print(f"[OK] Insecure S3 bucket created (No SSE, No Tags, No Versioning): {bucket_name}")

    # 2. Security Group com SSH (22) aberto para o mundo (0.0.0.0/0)
    if args.create_sg:
        if not args.vpc_id:
            raise SystemExit("❌ --vpc-id is required for Security Group creation")

        sg_id = ec2.create_security_group(
            GroupName=f"insecure-sg-{random_suffix()}",
            Description="World-open SSH for Security Hub & Governance testing",
            VpcId=args.vpc_id,
        )["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }]
        )
        print(f"[OK] Insecure Security Group created (Port 22 open to world): {sg_id}")

    # 3. Volume EBS sem criptografia (não-conforme para Governança/Security Hub)
    if args.create_ebs:
        az = f"{args.region}a"
        volume = ec2.create_volume(
            AvailabilityZone=az,
            Size=1,
            VolumeType="gp3",
            Encrypted=False  # Gera não conformidade de criptografia
        )
        vol_id = volume["VolumeId"]
        print(f"[OK] Unencrypted EBS volume created in {az}: {vol_id}")


if __name__ == "__main__":
    main()

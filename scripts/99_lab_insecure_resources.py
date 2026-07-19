import argparse
import random
import string

from lib.aws_clients import get_client


def random_suffix(size=6):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(size))


def main():
    parser = argparse.ArgumentParser(description="Create insecure AWS resources for Security Hub testing")
    parser.add_argument("--region", required=True)
    parser.add_argument("--create-s3", action="store_true")
    parser.add_argument("--create-sg", action="store_true")
    parser.add_argument("--vpc-id")
    args = parser.parse_args()

    s3 = get_client("s3", region=args.region)
    ec2 = get_client("ec2", region=args.region)

    if args.create_s3:
        bucket = f"insecure-shcp-{random_suffix()}"
        s3.create_bucket(Bucket=bucket)
        print(f"[OK] Insecure S3 bucket created: {bucket}")

    if args.create_sg:
        if not args.vpc_id:
            raise SystemExit("--vpc-id is required for Security Group creation")

        sg = ec2.create_security_group(
            GroupName=f"insecure-sg-{random_suffix()}",
            Description="World-open SSH for Security Hub testing",
            VpcId=args.vpc_id,
        )["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }]
        )

        print(f"[OK] Insecure Security Group created: {sg}")


if __name__ == "__main__":
    main()

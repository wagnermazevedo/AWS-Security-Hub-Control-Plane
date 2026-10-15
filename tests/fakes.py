"""Conta AWS em memória para testes offline.

Cada chamada é validada contra o modelo oficial do botocore (nome da operação,
parâmetros obrigatórios e tipos), então um parâmetro errado no código quebra
o teste do mesmo jeito que quebraria na AWS.
"""

import copy

import botocore.session
from botocore.exceptions import ClientError
from botocore.validate import validate_parameters

ACCOUNT = "210987654321"
REGION = "us-east-1"
_BOTO = botocore.session.get_session()
_REAL = {}


def _err(code):
    return ClientError({"Error": {"Code": code, "Message": "fake"}}, "op")


class _Paginator:
    def __init__(self, fn):
        self.fn = fn

    def paginate(self, PaginationConfig=None, **kwargs):  # noqa: N803
        yield self.fn(**kwargs)


class FakeService:
    service = ""

    def __init__(self, world):
        self.world = world
        if self.service not in _REAL:
            _REAL[self.service] = _BOTO.create_client(self.service, region_name=REGION,
                                                      aws_access_key_id="x", aws_secret_access_key="x")
        self._real = _REAL[self.service]
        self._model = _BOTO.get_service_model(self.service)

    def _check(self, name, params):
        op = self._model.operation_model(self._real.meta.method_to_api_mapping[name])
        if op.input_shape is not None:
            validate_parameters(params, op.input_shape)
        self.world.calls.append((self.service, name, params))

    def get_paginator(self, name):
        assert self._real.can_paginate(name), f"{name} não é paginável"
        return _Paginator(getattr(self, name))


class FakeSecurityHub(FakeService):
    service = "securityhub"

    def get_findings(self, **kw):
        self._check("get_findings", {**kw, "MaxResults": 100})
        filters = kw.get("Filters", {})
        controls = {f["Value"] for f in filters.get("ComplianceSecurityControlId", [])}
        statuses = {f["Value"] for f in filters.get("WorkflowStatus", [])}
        found = [copy.deepcopy(f) for f in self.world.findings
                 if f["Compliance"]["SecurityControlId"] in controls
                 and f["Workflow"]["Status"] in statuses
                 and f["Compliance"]["Status"] == "FAILED"]
        return {"Findings": found}

    def batch_update_findings(self, **kw):
        self._check("batch_update_findings", kw)
        for ident in kw["FindingIdentifiers"]:
            for f in self.world.findings:
                if f["Id"] == ident["Id"]:
                    f["Workflow"]["Status"] = kw["Workflow"]["Status"]
                    f["Note"] = kw["Note"]
        return {"ProcessedFindings": kw["FindingIdentifiers"], "UnprocessedFindings": []}


class FakeS3Control(FakeService):
    service = "s3control"

    def get_public_access_block(self, **kw):
        self._check("get_public_access_block", kw)
        if self.world.account_bpa is None:
            raise _err("NoSuchPublicAccessBlockConfiguration")
        return {"PublicAccessBlockConfiguration": dict(self.world.account_bpa)}

    def put_public_access_block(self, **kw):
        self._check("put_public_access_block", kw)
        self.world.account_bpa = dict(kw["PublicAccessBlockConfiguration"])
        return {}


class FakeS3(FakeService):
    service = "s3"

    def get_public_access_block(self, **kw):
        self._check("get_public_access_block", kw)
        bucket = self.world.buckets.get(kw["Bucket"])
        if bucket is None:
            raise _err("NoSuchBucket")
        return {"PublicAccessBlockConfiguration": dict(bucket["bpa"])}

    def put_public_access_block(self, **kw):
        self._check("put_public_access_block", kw)
        self.world.buckets[kw["Bucket"]]["bpa"] = dict(kw["PublicAccessBlockConfiguration"])
        return {}

    def get_bucket_tagging(self, **kw):
        self._check("get_bucket_tagging", kw)
        tags = self.world.buckets[kw["Bucket"]]["tags"]
        if not tags:
            raise _err("NoSuchTagSet")
        return {"TagSet": [{"Key": k, "Value": v} for k, v in tags.items()]}


class FakeEc2(FakeService):
    service = "ec2"

    def describe_security_groups(self, **kw):
        self._check("describe_security_groups", kw)
        groups = [copy.deepcopy(self.world.sgs[g]) for g in kw["GroupIds"] if g in self.world.sgs]
        if not groups:
            raise _err("InvalidGroup.NotFound")
        return {"SecurityGroups": groups}

    def revoke_security_group_ingress(self, **kw):
        self._check("revoke_security_group_ingress", kw)
        self.world.sgs[kw["GroupId"]]["IpPermissions"] = []
        return {"Return": True}

    def revoke_security_group_egress(self, **kw):
        self._check("revoke_security_group_egress", kw)
        self.world.sgs[kw["GroupId"]]["IpPermissionsEgress"] = []
        return {"Return": True}

    def get_ebs_encryption_by_default(self, **kw):
        self._check("get_ebs_encryption_by_default", kw)
        return {"EbsEncryptionByDefault": self.world.ebs_default}

    def enable_ebs_encryption_by_default(self, **kw):
        self._check("enable_ebs_encryption_by_default", kw)
        self.world.ebs_default = True
        return {"EbsEncryptionByDefault": True}


class FakeIam(FakeService):
    service = "iam"

    def get_account_summary(self, **kw):
        self._check("get_account_summary", kw)
        return {"SummaryMap": {"AccountAccessKeysPresent": self.world.root_keys}}


class FakeSts(FakeService):
    service = "sts"

    def get_caller_identity(self, **kw):
        self._check("get_caller_identity", kw)
        return {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:role/Admin"}


SERVICES = {"securityhub": FakeSecurityHub, "s3control": FakeS3Control, "s3": FakeS3,
            "ec2": FakeEc2, "iam": FakeIam, "sts": FakeSts}

OFF = {"BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}


def _finding(control, rtype, rid, severity, details=None):
    resource = {"Type": rtype, "Id": rid, "Region": REGION, "Partition": "aws"}
    if details:
        resource["Details"] = details
    return {
        "Id": f"arn:aws:securityhub:{REGION}:{ACCOUNT}:security-control/{control}/finding/{abs(hash(rid)) % 10**8}",
        "ProductArn": f"arn:aws:securityhub:{REGION}::product/aws/securityhub",
        "GeneratorId": f"security-control/{control}",
        "AwsAccountId": ACCOUNT,
        "Region": REGION,
        "Title": f"Finding {control}",
        "Severity": {"Label": severity},
        "Compliance": {"Status": "FAILED", "SecurityControlId": control},
        "Workflow": {"Status": "NEW"},
        "RecordState": "ACTIVE",
        "UpdatedAt": "2026-10-15T10:00:00Z",
        "Resources": [resource],
    }


class World:
    """Estado do laboratório inseguro, igual ao que o deploy.sh deixa."""

    def __init__(self):
        self.calls = []
        self.account_bpa = None
        self.ebs_default = False
        self.root_keys = 1
        self.buckets = {
            "shcp-insecure-lab-insecurebucket-abc": {"bpa": dict(OFF), "tags": {"Environment": "lab"}},
            "shcp-insecure-lab-exceptionbucket-def": {"bpa": dict(OFF), "tags": {
                "scp-exception": "Site estatico de testes", "exception-owner": "web-platform-team"}},
        }
        self.sgs = {"sg-0abc1234def56789a": {
            "GroupId": "sg-0abc1234def56789a", "GroupName": "default", "VpcId": "vpc-1",
            "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                               "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [], "PrefixListIds": [],
                               "UserIdGroupPairs": []}],
            "IpPermissionsEgress": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                     "Ipv6Ranges": [], "PrefixListIds": [], "UserIdGroupPairs": []}],
            "Tags": [],
        }}
        self.findings = [
            _finding("S3.1", "AwsAccount", f"AWS::::Account:{ACCOUNT}", "MEDIUM"),
            _finding("S3.8", "AwsS3Bucket", "arn:aws:s3:::shcp-insecure-lab-insecurebucket-abc", "HIGH"),
            _finding("S3.8", "AwsS3Bucket", "arn:aws:s3:::shcp-insecure-lab-exceptionbucket-def", "HIGH"),
            _finding("EC2.2", "AwsEc2SecurityGroup",
                     f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/sg-0abc1234def56789a", "HIGH",
                     {"AwsEc2SecurityGroup": {"GroupId": "sg-0abc1234def56789a", "GroupName": "default"}}),
            _finding("EC2.7", "AwsAccount", f"AWS::::Account:{ACCOUNT}", "MEDIUM"),
            _finding("IAM.4", "AwsAccount", f"AWS::::Account:{ACCOUNT}", "CRITICAL"),
        ]

    def client(self, sess, service):
        return SERVICES[service](self)

    @property
    def write_calls(self):
        return [c for c in self.calls if not c[1].startswith(("get_", "describe_", "list_"))]

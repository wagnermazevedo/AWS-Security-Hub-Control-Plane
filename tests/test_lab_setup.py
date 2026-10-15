"""Testes offline do setup do laboratório (scripts/99_securityhub_lab_setup.py)."""

import os
import runpy
import sys
import tempfile
import unittest
from unittest import mock

from botocore.exceptions import ClientError

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from recorder import Recorder  # noqa: E402

SCRIPT = os.path.join(REPO, "scripts", "99_securityhub_lab_setup.py")


def no_bpa():
    return ClientError({"Error": {"Code": "NoSuchPublicAccessBlockConfiguration", "Message": "x"}}, "op")


def make_clients():
    return {
        "sts": Recorder("sts", {"get_caller_identity": {"Account": "210987654321"}}),
        "s3": Recorder("s3"),
        "s3control": Recorder("s3control", {"get_public_access_block": {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}}),
        "ec2": Recorder("ec2", {"get_ebs_encryption_by_default": {"EbsEncryptionByDefault": True}}),
        "iam": Recorder("iam"),
        "config": Recorder("config", {"describe_configuration_recorders": {"ConfigurationRecorders": []}}),
        "securityhub": Recorder("securityhub"),
        "cloudformation": Recorder("cloudformation", {"describe_stacks": {"Stacks": [{
            "StackName": "shcp-insecure-lab", "CreationTime": "2026-10-15", "StackStatus": "CREATE_COMPLETE",
            "Outputs": [{"OutputKey": "InsecureBucketName", "OutputValue": "b"}]}]}}),
    }


class LabSetup(unittest.TestCase):
    def run_script(self, clients, *args):
        state = os.path.join(tempfile.mkdtemp(), ".account_state.json")
        with mock.patch("lib.aws.client", side_effect=lambda sess, svc: clients[svc]), \
             mock.patch("lib.aws.session", return_value=None), \
             mock.patch.object(sys, "argv", ["99", "--region", "us-east-1", *args]):
            ns = runpy.run_path(SCRIPT, run_name="not_main")
            ns["main"].__globals__["STATE_FILE"] = state
            ns["main"]()
        return state

    def names(self, clients):
        return [(svc, name) for c in clients.values() for svc, name, _ in c.calls]

    def test_setup_then_destroy_restores_account(self):
        clients = make_clients()
        state = os.path.join(tempfile.mkdtemp(), ".account_state.json")
        for args in (["--yes"], ["--destroy"]):
            with mock.patch("lib.aws.client", side_effect=lambda sess, svc: clients[svc]), \
                 mock.patch("lib.aws.session", return_value=None), \
                 mock.patch.object(sys, "argv", ["99", "--region", "us-east-1", *args]):
                ns = runpy.run_path(SCRIPT, run_name="not_main")
                ns["main"].__globals__["STATE_FILE"] = state
                ns["main"]()
        calls = self.names(clients)
        for expected in [("config", "put_configuration_recorder"), ("config", "start_configuration_recorder"),
                         ("securityhub", "enable_security_hub"), ("securityhub", "batch_enable_standards"),
                         ("s3control", "delete_public_access_block"), ("ec2", "disable_ebs_encryption_by_default"),
                         ("cloudformation", "create_stack"), ("cloudformation", "delete_stack"),
                         ("s3control", "put_public_access_block"), ("ec2", "enable_ebs_encryption_by_default")]:
            self.assertIn(expected, calls)
        self.assertFalse(os.path.exists(state))

    def test_setup_requires_confirmation(self):
        clients = make_clients()
        with mock.patch("builtins.input", return_value="nao"):
            with self.assertRaises(SystemExit):
                self.run_script(clients)
        self.assertNotIn(("cloudformation", "create_stack"), self.names(clients))

    def test_destroy_does_not_enable_what_was_off(self):
        clients = make_clients()
        clients["s3control"].errors["get_public_access_block"] = no_bpa()
        clients["ec2"].responses["get_ebs_encryption_by_default"] = {"EbsEncryptionByDefault": False}
        state = os.path.join(tempfile.mkdtemp(), ".account_state.json")
        for args in (["--yes", "--skip-securityhub"], ["--destroy"]):
            with mock.patch("lib.aws.client", side_effect=lambda sess, svc: clients[svc]), \
                 mock.patch("lib.aws.session", return_value=None), \
                 mock.patch.object(sys, "argv", ["99", "--region", "us-east-1", *args]):
                ns = runpy.run_path(SCRIPT, run_name="not_main")
                ns["main"].__globals__["STATE_FILE"] = state
                ns["main"]()
        calls = self.names(clients)
        self.assertNotIn(("ec2", "enable_ebs_encryption_by_default"), calls)
        self.assertNotIn(("securityhub", "enable_security_hub"), calls)


if __name__ == "__main__":
    unittest.main()

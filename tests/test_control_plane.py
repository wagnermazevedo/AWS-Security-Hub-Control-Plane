"""Testes offline do ciclo scan -> plan -> remediate.

Rodar: python3 -m unittest discover -s tests -v
"""

import glob
import json
import os
import runpy
import sys
import tempfile
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fakes import ACCOUNT, World  # noqa: E402
from lib.io import load_yaml  # noqa: E402

RULES = os.path.join(REPO, "config", "remediate_map.yaml")
EXPECTED = load_yaml(os.path.join(REPO, "tests", "expected_findings.yaml"))


class Runner:
    def __init__(self, world):
        self.world = world
        self.tmp = tempfile.mkdtemp()

    def _run(self, script, *args):
        with mock.patch("lib.aws.client", side_effect=self.world.client), \
             mock.patch("lib.aws.session", return_value=None), \
             mock.patch.object(sys, "argv", [script, *args]):
            try:
                runpy.run_path(os.path.join(REPO, "scripts", script), run_name="__main__")
            except SystemExit as exc:
                return exc.code
        return 0

    def _latest(self, pattern):
        return max(glob.glob(pattern), key=os.path.getmtime)

    def scan(self):
        out = os.path.join(self.tmp, "outputs")
        self._run("00_securityhub_scan.py", "--region", "us-east-1", "--output-dir", out)
        path = self._latest(os.path.join(out, "*", "securityhub_findings_export.yaml"))
        return path, load_yaml(path)

    def plan(self, scan_yaml):
        path = os.path.join(self.tmp, "remediation_plan.yaml")
        self._run("01_securityhub_plan.py", "--input-yaml", scan_yaml, "--rules", RULES, "--output-yaml", path)
        return path, load_yaml(path)

    def remediate(self, plan_path, mode):
        out = os.path.join(self.tmp, "rem")
        code = self._run("02_securityhub_remediate.py", "--region", "us-east-1", "--yaml", plan_path,
                         "--mode", mode, "--output-dir", out)
        with open(self._latest(os.path.join(out, "*", "securityhub_remediation_results.json")), encoding="utf-8") as f:
            return code, json.load(f)


def items_for(doc, control, resource_contains=""):
    return [i for i in doc["spec"]["items"]
            if i["control"] == control and resource_contains in (i["finding"]["resource"]["locator"] or "conta")]


class FullCycle(unittest.TestCase):
    def test_scan_matches_expected_findings_and_is_read_only(self):
        world = World()
        _, export = Runner(world).scan()
        self.assertEqual(world.write_calls, [])
        for expected in EXPECTED["expected"]:
            found = items_for(export, expected["control"], expected.get("resource_contains", ""))
            self.assertEqual(len(found), 1, expected)
            self.assertEqual(found[0]["verified_state"]["state"], expected["verified_state"], expected)

    def test_plan_decisions_follow_the_map(self):
        runner = Runner(World())
        _, plan = runner.plan(runner.scan()[0])
        for expected in EXPECTED["expected"]:
            item = items_for(plan, expected["control"], expected.get("resource_contains", ""))[0]
            self.assertEqual(item["decision"]["type"], expected["decision"], expected)

    def test_dry_run_changes_nothing(self):
        world = World()
        runner = Runner(world)
        plan_path, _ = runner.plan(runner.scan()[0])
        code, results = runner.remediate(plan_path, "dry-run")
        self.assertEqual(code, 0, results)
        self.assertEqual(world.write_calls, [])
        self.assertTrue(all(f["Workflow"]["Status"] == "NEW" for f in world.findings))

    def test_apply_fixes_resources_and_closes_findings(self):
        world = World()
        runner = Runner(world)
        plan_path, _ = runner.plan(runner.scan()[0])
        code, results = runner.remediate(plan_path, "apply")
        self.assertEqual(code, 0, results)

        self.assertTrue(all(world.account_bpa.values()))
        self.assertTrue(all(world.buckets["shcp-insecure-lab-insecurebucket-abc"]["bpa"].values()))
        self.assertFalse(any(world.buckets["shcp-insecure-lab-exceptionbucket-def"]["bpa"].values()),
                         "bucket com exceção não pode ser alterado")
        self.assertEqual(world.sgs["sg-0abc1234def56789a"]["IpPermissions"], [])
        self.assertEqual(world.sgs["sg-0abc1234def56789a"]["IpPermissionsEgress"], [])
        self.assertTrue(world.ebs_default)
        self.assertEqual(world.root_keys, 1, "IAM.4 nunca é corrigido por script")

        status = {(f["Compliance"]["SecurityControlId"], f["Resources"][0]["Id"].split(":")[-1]): f["Workflow"]["Status"]
                  for f in world.findings}
        for expected in EXPECTED["expected"]:
            match = [v for (c, r), v in status.items()
                     if c == expected["control"] and expected.get("resource_contains", "") in r]
            self.assertEqual(match, [expected["workflow_after_apply"]], expected)

        _, export = runner.scan()
        self.assertEqual({i["control"] for i in export["spec"]["items"]}, {"IAM.4"},
                         "depois do apply só resta o manual (NOTIFIED); a exceção ficou SUPPRESSED")

    def test_refuses_non_default_security_group(self):
        world = World()
        world.sgs["sg-0abc1234def56789a"]["GroupName"] = "app-sg"
        runner = Runner(world)
        plan_path, _ = runner.plan(runner.scan()[0])
        code, results = runner.remediate(plan_path, "apply")
        self.assertEqual(code, 2)
        ec2 = [r for r in results["spec"]["results"] if r["control"] == "EC2.2"][0]
        self.assertIn("REFUSED", ec2["message"])
        self.assertNotEqual(world.sgs["sg-0abc1234def56789a"]["IpPermissions"], [])

    def test_exception_without_owner_goes_manual(self):
        world = World()
        del world.buckets["shcp-insecure-lab-exceptionbucket-def"]["tags"]["exception-owner"]
        runner = Runner(world)
        _, plan = runner.plan(runner.scan()[0])
        item = items_for(plan, "S3.8", "exceptionbucket")[0]
        self.assertEqual(item["decision"]["type"], "MANUAL")
        self.assertIn("sem dono", item["decision"]["reason"])

    def test_stale_finding_is_no_action(self):
        world = World()
        world.ebs_default = True  # alguém já corrigiu; o Security Hub ainda não reavaliou
        runner = Runner(world)
        _, plan = runner.plan(runner.scan()[0])
        self.assertEqual(items_for(plan, "EC2.7")[0]["decision"]["type"], "NO_ACTION")

    def test_anonymized_plan_still_works_for_account_controls(self):
        """O test-control-plane.sh troca números de conta por 123456789012 no YAML."""
        world = World()
        runner = Runner(world)
        scan_yaml, _ = runner.scan()
        with open(scan_yaml, encoding="utf-8") as f:
            masked = f.read().replace(ACCOUNT, "123456789012")
        with open(scan_yaml, "w", encoding="utf-8") as f:
            f.write(masked)
        plan_path, _ = runner.plan(scan_yaml)
        code, results = runner.remediate(plan_path, "apply")
        self.assertEqual(code, 0, results)
        self.assertTrue(all(world.account_bpa.values()))


if __name__ == "__main__":
    unittest.main()


class ControlIncludes(unittest.TestCase):
    """Um arquivo por controle em config/controls/, lidos pelo include do remediate_map.yaml."""

    def _map(self, files, extra=""):
        from lib.rules import load_rules  # noqa: E402
        tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(tmp, "controls"))
        for name, body in files.items():
            with open(os.path.join(tmp, "controls", name), "w", encoding="utf-8") as f:
                f.write(body)
        path = os.path.join(tmp, "remediate_map.yaml")
        with open(path, "w", encoding="utf-8") as f:
            f.write("apiVersion: securityhub.shcp/v1\nkind: RemediateMap\ninclude:\n  - controls/*.yaml\n" + extra)
        return load_rules, path

    def test_repo_map_loads_every_control_file(self):
        from lib.rules import load_rules
        doc = load_rules(RULES)
        self.assertEqual(sorted(doc["controls"]), ["EC2.2", "EC2.7", "IAM.4", "S3.1", "S3.8"])
        self.assertEqual(doc["sources"]["S3.8"], os.path.join("controls", "S3.8.yaml"))

    def test_new_file_is_picked_up_and_disabled_file_is_skipped(self):
        load_rules, path = self._map({
            "GuardDuty.1.yaml": 'id: GuardDuty.1\ntitle: "GuardDuty habilitado"\ndecision: MANUAL\nreason: "teste"\n',
            "S3.1.yaml": "id: S3.1\ndecision: AUTO\naction: s3_account_public_access_block\nenabled: false\n",
        })
        self.assertEqual(list(load_rules(path)["controls"]), ["GuardDuty.1"])

    def test_duplicate_and_invalid_controls_are_rejected(self):
        from lib.rules import RulesError
        load_rules, path = self._map({"a.yaml": "id: S3.1\ndecision: MANUAL\n"},
                                     extra="controls:\n  S3.1:\n    decision: MANUAL\n")
        with self.assertRaisesRegex(RulesError, "duas vezes"):
            load_rules(path)
        load_rules, path = self._map({"a.yaml": "id: S3.1\ndecision: AUTO\n"})
        with self.assertRaisesRegex(RulesError, "não tem action"):
            load_rules(path)

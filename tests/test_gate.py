import copy
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("gate", ROOT / ".github" / "gate.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def event(base="a" * 40, head="b" * 40):
    repo = {"id": 7, "full_name": "sample/repo"}
    return {
        "repository": repo,
        "pull_request": {
            "number": 1, "state": "open",
            "base": {"repo": repo, "ref": "main", "sha": base},
            "head": {"repo": repo, "sha": head},
        },
    }


class GateTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {
            "GITHUB_REPOSITORY": "sample/repo", "GITHUB_RUN_NUMBER": "2",
            "GITHUB_RUN_ID": "20", "GITHUB_RUN_ATTEMPT": "1",
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        self.expected = {
            "base_sha": "a" * 40, "head_sha": "b" * 40,
            "policy_sha256": "c" * 64, "snapshot_sha256": "d" * 64,
            "policy": (ROOT / gate.POLICY).read_text(encoding="utf-8"),
            "files": [{"path": "src/example.py", "before": "old\n", "after": "new\n"}],
        }
        self.report = {
            **{key: self.expected[key] for key in (
                "base_sha", "head_sha", "policy_sha256", "snapshot_sha256"
            )},
            "complete": True, "reviewed_files": ["src/example.py"], "violations": [],
        }
        self.check = {
            "id": 100, "name": gate.CHECK, "external_id": gate.identity(),
            "status": "in_progress", "conclusion": None,
            "output": {"title": "Validated zero-violation review", "summary": "evidence"},
        }

    def output(self, report=None):
        return {"errors": [], "items": [{"type": "publish_review", "report": json.dumps(
            self.report if report is None else report
        )}]}

    def test_complete_zero_violation_review(self):
        self.assertEqual(gate.validate(self.output(), self.expected), [])

    def test_all_policy_violations_survive_validation(self):
        for rule, severity in (("SEC-001", "high"), ("SEC-002", "critical"),
                               ("SEC-003", "high"), ("SEC-004", "high"), ("SEC-005", "high")):
            finding = {
                "rule_id": rule, "severity": severity, "path": "src/example.py",
                "line": 1, "explanation": "Unsafe operation", "remediation": "Use safe data",
            }
            self.report["violations"] = [finding]
            self.assertEqual(gate.validate(self.output(), self.expected), [finding])

    def test_noop_missing_error_or_duplicate_result_cannot_pass(self):
        for output in ({}, {"items": []}, {"items": [{"type": "noop"}]},
                       {"items": [{"type": "report_incomplete"}]},
                       {"items": self.output()["items"] * 2},
                       {"items": self.output()["items"] + [{"type": "error"}]}):
            with self.subTest(output=output), self.assertRaises(gate.GateError):
                gate.validate(dict(output, errors=[]), self.expected)
        for errors in (None, ["tool error"], False):
            with self.assertRaises(gate.GateError):
                gate.validate(dict(self.output(), errors=errors), self.expected)

    def test_malformed_incomplete_or_wrong_revision_cannot_pass(self):
        changes = [
            ("complete", False), ("complete", "true"), ("complete", 1),
            ("head_sha", "e" * 40), ("base_sha", "f" * 40),
            ("policy_sha256", "0" * 64), ("snapshot_sha256", "1" * 64),
            ("reviewed_files", []), ("reviewed_files", ["src/example.py"] * 2),
            ("reviewed_files", ["README.md"]), ("violations", None),
        ]
        for key, value in changes:
            report = dict(self.report, **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(gate.GateError):
                gate.validate(self.output(report), self.expected)
        for conclusion in ("neutral", "skipped", "success"):
            with self.assertRaises(gate.GateError):
                gate.validate(self.output(dict(self.report, conclusion=conclusion)), self.expected)

    def test_duplicate_json_keys_and_invalid_findings_block(self):
        with self.assertRaises(gate.GateError):
            gate.load_json('{"complete":false,"complete":true}')
        self.report["violations"] = [{
            "rule_id": "SEC-001", "severity": "high", "path": "src/example.py",
            "line": 1, "explanation": "Unsafe", "remediation": "Parameterize",
        }]
        for key, value in (("rule_id", "UNKNOWN"), ("severity", "low"),
                           ("path", "other.py"), ("line", True), ("line", 2),
                           ("remediation", "")):
            report = copy.deepcopy(self.report)
            report["violations"][0][key] = value
            with self.subTest(key=key), self.assertRaises(gate.GateError):
                gate.validate(self.output(report), self.expected)

    def test_outside_fork_is_not_admitted(self):
        payload = event()
        payload["pull_request"]["head"]["repo"] = {"id": 99}
        with self.assertRaises(gate.GateError):
            gate.context(payload)

    def test_newer_run_or_attempt_prevents_stale_publication(self):
        for newer_id in ("policy:3:30:1", "policy:2:20:2"):
            newer = dict(self.check, id=101, external_id=newer_id)
            with patch.object(gate, "checks", return_value=[self.check, newer]):
                with self.assertRaises(gate.GateError):
                    gate.current_check("sample/repo", "b" * 40)

    def test_start_invalidates_old_success_before_creating_pending(self):
        old = dict(self.check, status="completed", conclusion="success",
                   external_id="policy:1:10:1")
        with patch.object(gate, "live_revision"), patch.object(gate, "checks", return_value=[old]), \
                patch.object(gate, "api") as api:
            gate.start(event())
        self.assertEqual(api.call_args_list[0].args[2]["conclusion"], "failure")
        self.assertEqual(api.call_args_list[1].args[2]["status"], "in_progress")
        self.assertEqual(api.call_args_list[1].args[2]["head_sha"], "b" * 40)

    def test_partial_rerun_cannot_start_inference_without_fresh_pending_check(self):
        with patch.object(gate, "checks", return_value=[self.check]), \
                patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "2"}), \
                patch.object(gate, "snapshot") as snapshot:
            with self.assertRaises(gate.GateError):
                gate.prepare(event())
            snapshot.assert_not_called()

    def test_finish_missing_agent_or_output_blocks(self):
        for title in ("Review pending", "Validated zero-violation review"):
            self.check["output"]["title"] = title
            with patch.object(gate, "current_check", return_value=self.check), \
                    patch.dict(os.environ, {"JOB_RESULTS": '{"agent":{"result":"failure"}}'}), \
                    patch.object(gate, "update") as update:
                with self.assertRaises(gate.GateError):
                    gate.finish(event())
            self.assertEqual(update.call_args.args[2], "failure")

    def test_completion_is_successful_for_a_complete_review_even_with_policy_findings(self):
        for title, status, conclusion in (
            ("Validated zero-violation review", "in_progress", None),
            ("Policy violations", "completed", "failure"),
        ):
            self.check.update(status=status, conclusion=conclusion)
            self.check["output"]["title"] = title
            results = {job: {"result": "success"}
                       for job in ("begin_review", "agent", "detection", "publish_review", "safe_outputs")}
            with patch.object(gate, "current_check", return_value=self.check), \
                    patch.dict(os.environ, {"JOB_RESULTS": json.dumps(results)}), \
                    patch.object(gate, "update") as update:
                gate.finish(event())
            update.assert_not_called()

    def test_completion_preserves_specific_publication_failure(self):
        self.check.update(status="completed", conclusion="failure")
        self.check["output"]["title"] = "Incomplete or invalid review"
        with patch.object(gate, "current_check", return_value=self.check), \
                patch.dict(os.environ, {"JOB_RESULTS": '{"publish_review":{"result":"failure"}}'}), \
                patch.object(gate, "update") as update:
            with self.assertRaises(gate.GateError):
                gate.finish(event())
            update.assert_not_called()

    def lifecycle(self, conclusion, action="completed", attempt=1, title=None,
                  live_base="a" * 40, recorded=True):
        run = {
            "id": 20, "path": gate.WORKFLOW, "event": "pull_request_target",
            "repository": {"full_name": "sample/repo"}, "run_attempt": attempt,
            "head_sha": "b" * 40, "conclusion": conclusion,
            "pull_requests": [event()["pull_request"]] if recorded else [],
        }
        if title:
            self.check["output"]["title"] = title
        pr = event(base=live_base)["pull_request"]
        def fake_api(method, route, body=None):
            if "/actions/runs/" in route:
                return run
            return pr
        with patch.object(gate, "api", side_effect=fake_api), \
                patch.object(gate, "pages", return_value=[pr]), \
                patch.object(gate, "checks", return_value=[self.check]), \
                patch.object(gate, "update") as update:
            gate.lifecycle({"workflow_run": run, "action": action})
        return update

    def test_only_completed_success_with_validated_review_releases_green(self):
        self.assertEqual(self.lifecycle("success").call_args.args[2], "success")
        for result in ("failure", "cancelled", "timed_out", "skipped", "neutral", None):
            self.assertEqual(self.lifecycle(result).call_args.args[2], "failure")
        self.assertEqual(self.lifecycle("success", title="Review pending").call_args.args[2],
                         "failure")

    def test_partial_rerun_invalidates_previous_attempt(self):
        self.check.update(status="completed", conclusion="success")
        self.assertEqual(self.lifecycle(None, action="in_progress", attempt=2).call_args.args[2],
                         "failure")

    def test_changed_base_or_missing_recorded_revision_blocks_release(self):
        self.assertEqual(self.lifecycle("success", live_base="f" * 40).call_args.args[2],
                         "failure")
        self.assertEqual(self.lifecycle("success", recorded=False).call_args.args[2],
                         "failure")

    def test_sql_example_treats_injection_as_data(self):
        from src.example import find_account
        with sqlite3.connect(":memory:") as connection:
            connection.execute("CREATE TABLE accounts (id INTEGER, email TEXT)")
            connection.execute("INSERT INTO accounts VALUES (?, ?)", (1, "safe@example.invalid"))
            self.assertEqual(find_account(connection, "safe@example.invalid")[0], 1)
            self.assertIsNone(find_account(connection, "' OR 1=1 --"))


class SnapshotTests(unittest.TestCase):
    def test_inventory_and_base_policy_include_docs_renames_and_deletions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(["git", "-C", directory, *args],
                                               stderr=subprocess.PIPE).decode().strip()
            git("init", "--initial-branch=main")
            git("config", "user.email", "test@example.invalid")
            git("config", "user.name", "Test")
            (root / "security").mkdir()
            (root / gate.POLICY).write_text("trusted policy\n")
            (root / "old.txt").write_text("rename this document\n")
            (root / "deleted.txt").write_text("deleted document\n")
            git("add", ".")
            git("commit", "-m", "base")
            base = git("rev-parse", "HEAD")
            (root / "old.txt").rename(root / "new.txt")
            (root / "deleted.txt").unlink()
            (root / gate.POLICY).write_text("PR replacement must not be authoritative\n")
            (root / "README.md").write_text("documentation-only change\n")
            git("add", ".")
            git("commit", "-m", "head")
            head = git("rev-parse", "HEAD")
            real_git = gate.git
            def local_git(*args):
                if args[0] == "fetch":
                    return b""
                return real_git("-C", directory, *args)
            with patch.dict(os.environ, {"GITHUB_REPOSITORY": "sample/repo"}), \
                    patch.object(gate, "git", side_effect=local_git):
                result = gate.snapshot(event(base, head))
                self.assertEqual(result["policy"], "trusted policy\n")
                files = {entry["path"]: entry for entry in result["files"]}
                self.assertEqual(set(files), {"README.md", "deleted.txt", "new.txt", gate.POLICY})
                self.assertTrue(files["new.txt"]["status"].startswith("R"))
                self.assertEqual(files["new.txt"]["previous_path"], "old.txt")
                self.assertIsNone(files["deleted.txt"]["after"])
                with patch.object(gate, "MAX_INPUT", 10), self.assertRaises(gate.GateError):
                    gate.snapshot(event(base, head))
                with patch.object(gate, "MAX_BLOB", 2), self.assertRaises(gate.GateError):
                    gate.snapshot(event(base, head))
                for content in (b"binary\0content", b"\xffinvalid UTF-8"):
                    (root / "unsupported.bin").write_bytes(content)
                    git("add", "unsupported.bin")
                    git("commit", "-m", "unsupported data")
                    with self.assertRaises(gate.GateError):
                        gate.snapshot(event(base, git("rev-parse", "HEAD")))


if __name__ == "__main__":
    unittest.main()

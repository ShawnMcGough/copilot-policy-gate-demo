"""Offline tests of the trusted workflow steps; no Copilot calls or fixture code execution.

Run locally on trusted workflow changes with Python, PyYAML, Git, and Bash.
Unsafe source strings below are non-executable review evidence in temporary repos.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = yaml.load(
    (ROOT / ".github" / "workflows" / "security-snapshot.yml").read_text(encoding="utf-8"),
    Loader=yaml.BaseLoader,
)
STEPS = WORKFLOW["jobs"]["audit"]["steps"]
PREPARE = next(step["run"] for step in STEPS if step.get("id") == "prepare")
PUBLISH = STEPS[-1]["run"]
POLICY_PATH = "security/organization-standards.md"
BASH = shutil.which("bash")
SAFE_SOURCE = 'connection.execute("SELECT id FROM accounts WHERE email = ?", (email,))\n'
UNSAFE_SOURCE = 'connection.execute("SELECT id FROM accounts WHERE email = \'" + email + "\'")\n'


class SnapshotAuditTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="snapshot-audit-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.repo = self.root / "repo"
        self.temp = self.root / "runner"
        self.repo.mkdir()
        self.temp.mkdir()
        self.env = {
            **os.environ,
            "RUNNER_TEMP": str(self.temp),
            "GITHUB_STEP_SUMMARY": str(self.temp / "summary.md"),
            **{f"{stage}_OUTCOME": "success" for stage in ("TRUST", "CHECKOUT", "PREPARE", "INSTALL", "REVIEW")},
        }
        self.git("init", "--quiet", "--initial-branch=main")
        self.git("config", "core.autocrlf", "false")
        self.write(POLICY_PATH, (ROOT / POLICY_PATH).read_text(encoding="utf-8"))
        self.write("src/query.py", SAFE_SOURCE)
        self.write("README.md", "Example repository.\n")
        self.commit()

    def git(self, *args, input=None):
        return subprocess.run(
            ["git", *args], cwd=self.repo, input=input, text=True,
            encoding="utf-8", capture_output=True, check=True,
        ).stdout.strip()

    def write(self, name, content):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")

    def commit(self):
        self.git("add", "--all")
        self.git("-c", "user.name=Offline test", "-c", "user.email=offline@example.invalid",
                 "commit", "--quiet", "--allow-empty", "-m", "Offline fixture")
        return self.git("rev-parse", "HEAD")

    def run_step(self, script):
        path = self.temp / "step.py"
        path.write_text(script, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(path)], cwd=self.repo, env=self.env,
            capture_output=True, text=True, encoding="utf-8",
        )

    def prepare(self, success=True):
        for name in ("prompt.txt", "snapshot.json"):
            (self.temp / name).unlink(missing_ok=True)
        result = self.run_step(PREPARE)
        self.assertEqual(result.returncode, 0 if success else 1, result.stderr)
        self.manifest = json.loads((self.temp / "snapshot.json").read_text(encoding="utf-8"))
        self.assertEqual(self.manifest["prepared"], success)
        if success:
            prompt = (self.temp / "prompt.txt").read_text(encoding="utf-8")
            return json.loads(prompt.split("Review input:\n", 1)[1])
        self.assertFalse((self.temp / "prompt.txt").exists())
        self.env["PREPARE_OUTCOME"] = "failure"

    def report(self, **overrides):
        return {
            "snapshot_commit": self.manifest["commit"],
            "policy_blob": self.manifest["policy_blob"],
            "reviewed_paths": [f["path"] for f in self.manifest["files"]],
            "complete": True, "summary": "Offline fixture assessment.", "violations": [],
            **overrides,
        }

    def events(self, report):
        return [
            {"type": "assistant.message", "data": {"content": json.dumps(report)}},
            {"type": "result", "exitCode": 0},
        ]

    def publish(self, events, status):
        summary_path = Path(self.env["GITHUB_STEP_SUMMARY"])
        summary_path.unlink(missing_ok=True)
        raw = events if isinstance(events, str) else "\n".join(json.dumps(e) for e in events)
        (self.temp / "events.jsonl").write_text(raw, encoding="utf-8")
        result = self.run_step(PUBLISH)
        self.assertEqual(result.returncode, 0 if status == "PASS" else 1, result.stderr)
        summary = summary_path.read_text(encoding="utf-8")
        self.assertIn(f"**{status}**", summary)
        self.assertNotIn("do-not-publish-this-diagnostic", summary)
        return summary

    def violation(self):
        return {
            "rule_id": "SEC-001", "severity": "high", "path": "src/query.py", "line": 1,
            "explanation": "Untrusted email is concatenated into executed SQL.",
            "remediation": "Use a placeholder and a separate parameter collection.",
        }

    def test_clean_snapshot_and_uncommitted_policy_are_pinned_to_one_commit(self):
        commit = self.git("rev-parse", "HEAD")
        committed_policy = self.git("show", f"HEAD:{POLICY_PATH}") + "\n"
        self.write(POLICY_PATH, "Uncommitted replacement must not become the trusted policy.\n")
        evidence = self.prepare()
        self.assertEqual(evidence["snapshot_commit"], commit)
        self.assertEqual(evidence["policy"]["content"], committed_policy)
        self.assertEqual(evidence["policy"]["blob"], self.git("rev-parse", f"HEAD:{POLICY_PATH}"))
        source = next(f for f in evidence["files"] if f["path"] == "src/query.py")
        self.assertEqual(source["content"], f"1: {SAFE_SOURCE.rstrip()}")
        summary = self.publish(self.events(self.report()), "PASS")
        self.assertIn(commit, summary)
        self.assertIn("3/3", summary)

    def test_existing_violation_outside_latest_diff_is_reviewed_and_reported(self):
        self.write("src/query.py", UNSAFE_SOURCE)
        self.commit()
        self.write("README.md", "Unrelated latest change.\n")
        self.commit()
        self.assertNotIn("src/query.py", self.git("diff", "--name-only", "HEAD~1", "HEAD"))
        evidence = self.prepare()
        source = next(f for f in evidence["files"] if f["path"] == "src/query.py")
        self.assertIn(UNSAFE_SOURCE.rstrip(), source["content"])
        summary = self.publish(self.events(self.report(violations=[self.violation()])), "FAIL")
        self.assertIn("SEC-001", summary)
        self.assertIn("src/query.py:1", summary)
        self.assertIn("Use a placeholder", summary)

    def test_updated_policy_applies_to_unchanged_snapshot_code(self):
        self.write(POLICY_PATH, "# Old policy fixture\nDo not log secrets.\n")
        self.write("src/query.py", UNSAFE_SOURCE)
        self.commit()
        source_blob = self.git("rev-parse", "HEAD:src/query.py")
        updated = (ROOT / POLICY_PATH).read_text(encoding="utf-8")
        self.write(POLICY_PATH, updated)
        self.commit()
        self.assertEqual(self.git("diff", "--name-only", "HEAD~1", "HEAD"), POLICY_PATH)
        evidence = self.prepare()
        self.assertEqual(evidence["policy"]["content"], updated)
        source = next(f for f in evidence["files"] if f["path"] == "src/query.py")
        self.assertEqual(source["blob"], source_blob)
        self.assertIn("all existing behavior", (self.temp / "prompt.txt").read_text(encoding="utf-8"))
        self.publish(self.events(self.report(violations=[self.violation()])), "FAIL")

    def test_incomplete_coverage_never_passes_and_preserves_findings(self):
        self.prepare()
        for changes in (
            {"complete": False},
            {"reviewed_paths": ["README.md"]},
            {"complete": False, "reviewed_paths": [], "violations": [self.violation()]},
        ):
            with self.subTest(changes=changes):
                summary = self.publish(self.events(self.report(**changes)), "INCOMPLETE")
                if changes.get("violations"):
                    self.assertIn("SEC-001", summary)

    def test_malformed_reports_and_unclean_cli_events_never_pass(self):
        self.prepare()
        valid = self.events(self.report())
        cases = [
            "", "not JSON", '[]', json.dumps({"type": "result", "exitCode": 0}),
            [{"type": "assistant.message", "data": {"content": "not JSON"}}, valid[-1]],
            valid + [valid[0]],
            valid + [{"type": "session.error", "data": {"message": "do-not-publish-this-diagnostic"}}],
            [valid[0], {"type": "result", "exitCode": 1}],
            [valid[0], {"type": "result", "exitCode": False}],
            self.events(self.report(snapshot_commit="wrong")),
            self.events(self.report(policy_blob="wrong")),
            self.events(self.report(complete="true")),
            self.events(self.report(reviewed_paths=["README.md", "README.md"])),
            self.events(self.report(reviewed_paths=["unknown.py"])),
            self.events(self.report(violations=[{**self.violation(), "line": 999}])),
        ]
        for index, events in enumerate(cases):
            with self.subTest(case=index):
                self.publish(events, "ERROR")

    def test_early_failures_still_produce_summary_and_reject_success_shaped_output(self):
        self.prepare()
        for stage in ("TRUST", "CHECKOUT", "INSTALL", "REVIEW"):
            with self.subTest(stage=stage):
                self.env[f"{stage}_OUTCOME"] = "failure"
                self.publish(self.events(self.report()), "ERROR")
                self.env[f"{stage}_OUTCOME"] = "success"
        (self.temp / "snapshot.json").unlink()
        self.env["CHECKOUT_OUTCOME"] = "failure"
        self.publish("", "ERROR")

    def test_cli_shell_failure_preserves_summary_without_publishing_raw_output(self):
        self.prepare()
        mock_bin = self.temp / "bin"
        mock_bin.mkdir()
        mock_cli = mock_bin / "copilot"
        mock_cli.write_text(
            '#!/usr/bin/env bash\nprintf "%s\\n" "$MOCK_EVENTS"\n'
            'echo do-not-publish-this-diagnostic >&2\nexit 1\n',
            encoding="utf-8", newline="\n",
        )
        mock_cli.chmod(0o755)
        review = next(step["run"] for step in STEPS if step.get("id") == "review")
        prefix = 'export PATH="$MOCK_BIN:$PATH"\n'
        if os.name == "nt":
            prefix = 'MOCK_BIN="$(cygpath -u "$MOCK_BIN")"\n' + prefix
        prefix += '[[ "$(command -v copilot)" == "$MOCK_BIN/copilot" ]] || exit 99\n'
        result = subprocess.run(
            [BASH, "-c", prefix + review], cwd=self.temp, capture_output=True,
            env={**self.env, "MOCK_BIN": str(mock_bin),
                 "COPILOT_HOME": str(self.temp / "copilot-home"),
                 "COPILOT_GITHUB_TOKEN": "nonfunctional-offline-placeholder",
                 "MOCK_EVENTS": "\n".join(json.dumps(e) for e in self.events(self.report()))},
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")
        self.env["REVIEW_OUTCOME"] = "failure"
        summary = self.publish((self.temp / "events.jsonl").read_text(encoding="utf-8"), "ERROR")
        self.assertIn("CLI installation/review failed", summary)

    def test_binary_non_utf8_lfs_and_oversized_input_are_rejected_without_truncation(self):
        for data in (
            b"binary\0content", b"\xff\xfe",
            b"version https://git-lfs.github.com/spec/v1\noid sha256:nonfunctional-fixture\n",
            b"a" * (128 * 1024 + 1),
            b"\n" * 30000,
        ):
            with self.subTest(size=len(data)):
                (self.repo / "unsupported").write_bytes(data)
                self.commit()
                self.prepare(success=False)
                summary = self.publish("", "INCOMPLETE")
                self.assertIn("Input prepared in full: no", summary)
                if data == b"\n" * 30000:
                    self.assertIn("256 KiB", self.manifest["error"])

    def test_symlinks_submodules_and_file_count_limit_are_rejected(self):
        blob = self.git("hash-object", "-w", "--stdin", input="src/query.py")
        for mode, object_id in (("120000", blob), ("160000", self.git("rev-parse", "HEAD"))):
            with self.subTest(mode=mode):
                self.git("update-index", "--add", "--cacheinfo", f"{mode},{object_id},unsupported")
                self.git("-c", "user.name=Offline test", "-c", "user.email=offline@example.invalid",
                         "commit", "--quiet", "-m", "Unsupported fixture")
                self.prepare(success=False)
                self.assertIn("Unsupported tracked entry", self.manifest["error"])
                self.git("update-index", "--force-remove", "unsupported")
        for index in range(198):
            self.write(f"many/{index}.txt", "")
        self.commit()
        self.prepare(success=False)
        self.assertIn("200 files", self.manifest["error"])

    def test_trusted_ref_guard_and_workflow_contract(self):
        self.assertEqual(WORKFLOW["on"], {"schedule": [{"cron": "17 9 * * 1"}], "workflow_dispatch": ""})
        self.assertEqual(WORKFLOW["permissions"], {"contents": "read"})
        self.assertEqual(STEPS[-1]["if"], "always()")
        base_env = {
            **os.environ, "GITHUB_REPOSITORY": "owner/repo", "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "WORKFLOW_REF": "owner/repo/.github/workflows/security-snapshot.yml@refs/heads/main",
        }
        for change, expected in (
            ({}, 0), ({"GITHUB_EVENT_NAME": "schedule"}, 0),
            ({"GITHUB_REF": "refs/heads/feature"}, 1),
            ({"WORKFLOW_REF": "owner/repo/.github/workflows/security-snapshot.yml@refs/heads/feature"}, 1),
            ({"GITHUB_EVENT_NAME": "pull_request"}, 1),
        ):
            with self.subTest(change=change):
                result = subprocess.run([BASH, "-c", STEPS[0]["run"]], env={**base_env, **change}, capture_output=True)
                self.assertEqual(result.returncode, expected, result.stderr)
        for step in STEPS:
            if step.get("shell") == "python":
                compile(step["run"], step["name"], "exec")
            elif "run" in step:
                subprocess.run([BASH, "-n"], input=step["run"].encode("utf-8"), check=True)

    def test_actual_repository_snapshot_fits_limits_and_includes_every_file(self):
        paths = subprocess.check_output(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT,
        ).decode("utf-8").strip("\0").split("\0")
        for path in paths:
            target = self.repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / path).read_bytes())
        self.commit()
        evidence = self.prepare()
        self.assertTrue(set(paths) <= {file["path"] for file in evidence["files"]})
        self.publish(self.events(self.report()), "PASS")


if __name__ == "__main__":
    unittest.main()

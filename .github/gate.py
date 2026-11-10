"""Trusted data/Checks adapter. Security analysis belongs to Copilot, not here."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.request

CHECK = "Organization Security Standards"
WORKFLOW = ".github/workflows/security-compliance.lock.yml"
POLICY = "security/organization-standards.md"
MAX_FILES = 50
MAX_BLOB = 262144
MAX_INPUT = 524288


class GateError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise GateError(message)


def load_json(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=unique)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def git(*args):
    return subprocess.check_output(
        ["git", "-c", "core.hooksPath=/dev/null", *args], stderr=subprocess.PIPE
    )


def api(method, route, body=None):
    require(route.startswith("/repos/"), "Unexpected API route")
    request = urllib.request.Request(
        "https://api.github.com" + route,
        data=None if body is None else canonical(body).encode(),
        method=method,
        headers={
            "Authorization": "Bearer " + os.environ["GH_TOKEN"],
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise GateError(f"GitHub API {method} failed (HTTP {error.code})") from None


def pages(route, key=None):
    result = []
    for page in range(1, 21):
        separator = "&" if "?" in route else "?"
        data = api("GET", f"{route}{separator}per_page=100&page={page}")
        values = data[key] if key else data
        result.extend(values)
        if len(values) < 100:
            return result
    raise GateError("GitHub pagination limit exceeded; review blocked")


def context(event):
    pr = event["pull_request"]
    repo = os.environ["GITHUB_REPOSITORY"]
    require(event["repository"]["full_name"] == repo, "Repository mismatch")
    require(pr["base"]["repo"]["full_name"] == repo and pr["base"]["ref"] == "main",
            "Only this repository's main branch is supported")
    require(pr["head"]["repo"] is not None
            and pr["head"]["repo"]["id"] == event["repository"]["id"],
            "Outside fork PRs are not admitted")
    base, head = pr["base"]["sha"], pr["head"]["sha"]
    require(all(re.fullmatch("[0-9a-f]{40}", sha) for sha in (base, head)),
            "Invalid immutable revision")
    return repo, pr["number"], base, head


def snapshot(event):
    repo, number, base, head = context(event)
    git("fetch", "--no-tags", "--no-recurse-submodules", "--depth=1", "origin", base, head)
    policy_blob = git("rev-parse", f"{base}:{POLICY}").decode().strip()

    def text_blob(sha):
        require(int(git("cat-file", "-s", sha)) <= MAX_BLOB, "Blob exceeds 256 KiB")
        raw = git("cat-file", "blob", sha)
        require(b"\0" not in raw, "Binary content is unsupported")
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            raise GateError("Non-UTF-8 content is unsupported") from None

    policy = text_blob(policy_blob)
    entries = git("diff", "--raw", "--no-abbrev", "-z", "--find-renames",
                  "--no-ext-diff", "--no-textconv", base, head, "--").split(b"\0")
    files = []
    index = 0
    while index < len(entries) - 1:
        old_mode, new_mode, old_blob, new_blob, status = entries[index].decode().split()
        old_mode = old_mode.removeprefix(":")
        index += 1
        old_path = entries[index].decode("utf-8")
        index += 1
        path = old_path
        if status.startswith(("R", "C")):
            path = entries[index].decode("utf-8")
            index += 1
        require(all(mode in ("000000", "100644", "100755") for mode in (old_mode, new_mode)),
                "Symlinks and submodules are unsupported")
        require(not any(ord(char) < 32 for char in path + old_path),
                "Control characters in file paths are unsupported")
        files.append({
            "path": path, "previous_path": old_path, "status": status,
            "before_blob": old_blob, "after_blob": new_blob,
            "before": None if old_mode == "000000" else text_blob(old_blob),
            "after": None if new_mode == "000000" else text_blob(new_blob),
        })
        require(len(files) <= MAX_FILES, "More than 50 changed files")
    result = {
        "repository": repo, "pr": number, "base_sha": base, "head_sha": head,
        "policy_path": POLICY, "policy_blob": policy_blob,
        "policy_sha256": digest(policy), "policy": policy, "files": files,
    }
    require(len(canonical(result).encode()) <= MAX_INPUT, "Review input exceeds 512 KiB")
    result["snapshot_sha256"] = digest(canonical(result))
    return result


def validate(output, expected):
    require(isinstance(output, dict) and isinstance(output.get("items"), list),
            "Missing safe-output items")
    items = output["items"]
    require(len(items) == 1 and isinstance(items[0], dict)
            and items[0].get("type") == "publish_review",
            "Exactly one publish_review result is required; noop/errors cannot pass")
    require(isinstance(items[0].get("report"), str), "Missing structured report")
    report = load_json(items[0]["report"])
    keys = {"base_sha", "head_sha", "policy_sha256", "snapshot_sha256",
            "reviewed_files", "complete", "violations"}
    require(isinstance(report, dict) and set(report) == keys, "Invalid report fields")
    require(report["complete"] is True, "Copilot did not complete the entire review")
    for key in ("base_sha", "head_sha", "policy_sha256", "snapshot_sha256"):
        require(report[key] == expected[key], f"Review evidence mismatch: {key}")
    paths = [entry["path"] for entry in expected["files"]]
    reviewed = report["reviewed_files"]
    require(isinstance(reviewed, list) and all(isinstance(p, str) for p in reviewed)
            and sorted(reviewed) == sorted(paths), "Incomplete or duplicate file coverage")
    violations = report["violations"]
    require(isinstance(violations, list) and len(violations) <= 50, "Invalid findings list")
    rules = dict(re.findall(
        r"^## (SEC-\d+): .+ \((critical|high|medium|low)\)$",
        expected["policy"], re.MULTILINE,
    ))
    require(bool(rules), "Trusted policy has no recognized rule identifiers")
    for finding in violations:
        require(isinstance(finding, dict) and set(finding) == {
            "rule_id", "severity", "path", "line", "explanation", "remediation"
        }, "Invalid finding fields")
        require(isinstance(finding["rule_id"], str) and finding["rule_id"] in rules,
                "Unknown policy rule")
        require(finding["severity"] == rules[finding["rule_id"]], "Invalid severity")
        require(isinstance(finding["path"], str) and finding["path"] in paths,
                "Finding is outside the reviewed files")
        entry = expected["files"][paths.index(finding["path"])]
        line_count = max(len((entry["before"] or "").splitlines()),
                         len((entry["after"] or "").splitlines()), 1)
        require(type(finding["line"]) is int and 1 <= finding["line"] <= line_count,
                "Invalid finding line")
        for key in ("explanation", "remediation"):
            require(isinstance(finding[key], str) and 0 < len(finding[key].strip()) <= 2000,
                    f"Missing or oversized finding {key}")
    return violations


def identity():
    return "policy:{}:{}:{}".format(
        os.environ["GITHUB_RUN_NUMBER"], os.environ["GITHUB_RUN_ID"],
        os.environ["GITHUB_RUN_ATTEMPT"],
    )


def order(check):
    match = re.fullmatch(r"policy:(\d+):(\d+):(\d+)", check.get("external_id") or "")
    require(match is not None, "Unrecognized check provenance")
    number, run_id, attempt = map(int, match.groups())
    return number, attempt, run_id


def checks(repo, sha):
    return [check for check in pages(
        f"/repos/{repo}/commits/{sha}/check-runs?filter=all", "check_runs"
    ) if check["name"] == CHECK and check["app"]["slug"] == "github-actions"]


def update(repo, check, conclusion, title, summary):
    require(conclusion in ("success", "failure"), "Only success or failure is allowed")
    api("PATCH", f"/repos/{repo}/check-runs/{check['id']}", {
        "status": "completed", "conclusion": conclusion,
        "output": {"title": title, "summary": summary},
    })


def current_check(repo, head):
    all_checks = checks(repo, head)
    matches = [check for check in all_checks if check["external_id"] == identity()]
    require(len(matches) == 1, "No unique pending check for this run attempt")
    selected = matches[0]
    require(all(order(check) <= order(selected) for check in all_checks),
            "This review has been superseded")
    return selected


def live_revision(repo, number, base, head):
    live = api("GET", f"/repos/{repo}/pulls/{number}")
    require(live["state"] == "open" and live["base"]["ref"] == "main"
            and live["base"]["sha"] == base and live["head"]["sha"] == head,
            "PR closed, retargeted, or moved; a fresh review is required")
    run = api("GET", f"/repos/{repo}/actions/runs/{os.environ['GITHUB_RUN_ID']}")
    require(run["run_attempt"] == int(os.environ["GITHUB_RUN_ATTEMPT"])
            and run["status"] == "in_progress", "Stale or cancelled workflow attempt")


def start(event):
    repo, number, base, head = context(event)
    live_revision(repo, number, base, head)
    prior = checks(repo, head)
    candidate = {"external_id": identity()}
    require(all(order(check) <= order(candidate) for check in prior),
            "A newer review already started")
    for check in prior:
        update(repo, check, "failure", "Superseded review",
               "A new review started. A previous successful verdict must not be reused.")
    run_url = f"https://github.com/{repo}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
    api("POST", f"/repos/{repo}/check-runs", {
        "name": CHECK, "head_sha": head, "external_id": identity(),
        "status": "in_progress", "details_url": run_url,
        "output": {"title": "Review pending", "summary":
                   f"Reviewing `{head}` against trusted base `{base}`. No verdict yet."},
    })


def publish(event):
    repo, number, base, head = context(event)
    check = current_check(repo, head)
    try:
        require(os.environ.get("GH_AW_SAFE_OUTPUTS_STAGED") != "true",
                "Staged output cannot establish compliance")
        require(os.environ.get("AGENT_RESULT") == "success"
                and os.environ.get("DETECTION_RESULT") == "success"
                and os.environ.get("GH_AW_DETECTION_CONCLUSION") == "success",
                "Agent or threat-detection lifecycle was not successful")
        live_revision(repo, number, base, head)
        expected = snapshot(event)
        output_file = Path(os.environ["GH_AW_AGENT_OUTPUT"])
        require(output_file.stat().st_size <= 262144, "Oversized agent output")
        findings = validate(load_json(output_file.read_text(encoding="utf-8")), expected)
        summary = (f"Head: `{head}`\n\nBase: `{base}`\n\n"
                   f"Policy SHA-256: `{expected['policy_sha256']}`\n\n"
                   f"Reviewed all {len(expected['files'])} changed files.\n\n")
        for finding in findings:
            summary += (
                f"**{finding['rule_id']} ({finding['severity']})** - "
                f"`{finding['path']}:{finding['line']}`\n\n"
                f"{finding['explanation']}\n\nFix: {finding['remediation']}\n\n"
            )
        require(len(summary.encode()) <= 60000, "Findings exceed Check output limit")
        live_revision(repo, number, base, head)
        current_check(repo, head)
        if findings:
            update(repo, check, "failure", "Policy violations", summary)
        else:
            # Success is released only after the parent workflow completes successfully.
            api("PATCH", f"/repos/{repo}/check-runs/{check['id']}", {
                "status": "in_progress",
                "output": {"title": "Validated zero-violation review", "summary": summary},
            })
    except (GateError, ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        update(repo, check, "failure", "Incomplete or invalid review",
               f"No compliance approval was issued. {type(error).__name__}. "
               "Inspect the workflow logs; fix the infrastructure or review output and rerun.")
        raise


def finish(event):
    repo, _, _, head = context(event)
    check = current_check(repo, head)
    if check["status"] != "completed":
        results = json.loads(os.environ["JOB_RESULTS"])
        if (check["output"]["title"] == "Validated zero-violation review"
                and all(results.get(job, {}).get("result") == "success"
                        for job in ("agent", "detection", "publish_review"))):
            return
        update(repo, check, "failure", "Review unavailable",
               "Copilot analysis/publication did not complete. Configure the repository "
               "Actions secret COPILOT_GITHUB_TOKEN using a Copilot-enabled account's "
               "fine-grained PAT (Copilot Requests: Read), then rerun all jobs. "
               "Provider errors, cancellation, missing output and incomplete reviews block.")


def lifecycle(event):
    run = event["workflow_run"]
    repo = os.environ["GITHUB_REPOSITORY"]
    require(run["path"] == WORKFLOW and run["event"] == "pull_request_target"
            and run["repository"]["full_name"] == repo, "Unexpected workflow provenance")
    current = api("GET", f"/repos/{repo}/actions/runs/{run['id']}")
    if current["run_attempt"] != run["run_attempt"]:
        return
    prs = pages(f"/repos/{repo}/pulls?state=open&base=main")
    for pr in prs:
        head = pr["head"]["sha"]
        for check in checks(repo, head):
            _, attempt, run_id = order(check)
            if run_id != run["id"]:
                continue
            if attempt < run["run_attempt"]:
                update(repo, check, "failure", "Rerun requires a fresh verdict",
                       "Previous attempts cannot approve a rerun. Rerun all jobs, not only failed jobs.")
            elif attempt == run["run_attempt"] and event["action"] == "completed":
                newest = all(order(other) <= order(check) for other in checks(repo, head))
                live = api("GET", f"/repos/{repo}/pulls/{pr['number']}")
                base_current = live["base"]["sha"] == run["head_sha"]
                if (newest and base_current and live["head"]["sha"] == head
                        and current["conclusion"] == "success"
                        and check["status"] == "in_progress"
                        and check["output"]["title"] == "Validated zero-violation review"):
                    update(repo, check, "success", "Compliant with the sample policy",
                           check["output"]["summary"])
                elif check["conclusion"] != "failure":
                    update(repo, check, "failure", "No completed compliance approval",
                           "The workflow failed, was cancelled, moved, or did not publish "
                           "a complete validated review. Rerun all jobs on the current revision.")


def main():
    event = load_json(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    command = sys.argv[1]
    if command == "prepare":
        Path("/tmp/gh-aw/review-input.json").write_text(
            canonical(snapshot(event)), encoding="utf-8"
        )
    else:
        {"start": start, "publish": publish, "finish": finish,
         "lifecycle": lifecycle}[command](event)


if __name__ == "__main__":
    try:
        main()
    except (GateError, ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        # Never echo HTTP bodies, file contents, or credential-bearing exceptions.
        message = str(error) if isinstance(error, GateError) else type(error).__name__
        print(f"::error::Policy gate blocked: {message}", file=sys.stderr)
        sys.exit(1)

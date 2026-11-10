# Copilot + Markdown policy gate

A public, dependency-free demonstration of a **required security-compliance
check**, not just an optional AI review comment. The standards are a fictional
[public sample](security/organization-standards.md), never confidential policy.

**Setup is in progress.** Live-run evidence and protection settings will be
recorded below once verified. Do not treat the initial bootstrap as protected.

## How it works

GitHub Agentic Workflows runs its official Copilot engine on trusted
same-repository PR events targeting `main`. The Markdown workflow is compiled
with **github/gh-aw v1.2.2**, pinned to
`399a445fe2d8926c616b54b1b82a16b5b2be4445`; do not edit the generated lockfile.

The trusted helper extracts the event's immutable base/head Git objects as text
data, without checking out or executing the PR. It uses the policy from the base,
not the proposed replacement. Copilot reviews all changed files in its official
sandbox/firewall with no shell, edits, or GitHub tools. The helper does **not**
analyze source for security issues: it only validates evidence and manages checks.

The `Organization Security Standards` check starts pending. A supported custom
safe-output job accepts exactly one complete structured report, bound to the
base/head revisions, policy digest, snapshot digest and entire file inventory.
Any violation, missing coverage, malformed result, error or incomplete analysis
blocks. The built-in publisher is not used because it also accepts neutral/skipped
conclusions, which GitHub considers passing required checks.

A small trusted `workflow_run` lifecycle job releases success only after the
analysis workflow finishes successfully. It also invalidates older rerun attempts
and failed/cancelled runs. Results never move to a newer PR head. Operational jobs
may be green while the required compliance check is red for a policy violation.

## Owner setup

1. Use a Copilot-enabled account. Create a **fine-grained PAT**, resource owner
   your user account, with **Account permissions > Copilot Requests: Read**.
   The PAT's display name is arbitrary.
2. Save its value directly under this repository's **Settings > Secrets and
   variables > Actions** with the exact secret name `COPILOT_GITHUB_TOKEN`.
   Do not paste the token into chat, a file, an issue, or a command log.
3. Configure an active Actions event policy scoped to
   `.github/workflows/security-compliance.lock.yml`, allowing
   `pull_request_target`. This explicitly replaces GitHub's applicable default
   restriction, scheduled for enforcement December 2, 2026. Do not enable all
   forks or read-role actor access.
4. After the one-time bootstrap and a genuine emitted check, activate the `main`
   ruleset: PR required, zero additional human approvals, required check named
   `Organization Security Standards` bound to its observed GitHub Actions App,
   strict up-to-date branch requirement, no force push/deletion, **no bypasses**.
   Never disable protection to perform routine maintenance.

This personal repository does not assume organization-billed
`copilot-requests: write`. A secret name existing does not prove the PAT has a
valid entitlement; the actual inference run must succeed.

## Demonstration

Open the PR's **Checks** tab and the named check's **Details**. Findings contain
the sample rule ID, severity, file/line, explanation and fix.

- A compliant parameterized-query change should pass.
- Replacing parameter binding with SQL string interpolation should fail SEC-001.
- Restoring parameter binding on that PR should trigger a fresh review and pass.
- A new bad commit after green must receive a new blocking verdict.
- Editing the policy in the PR does not change its current evaluator.

Demonstration PRs remain **unmerged**. No real credentials or deployed services
are involved. Outside fork PRs are excluded from credentialed analysis and cannot
satisfy the required check. There are no path filters, including for docs changes.

## Limits and failure recovery

- Maximum 50 changed files, 256 KiB per text blob, 512 KiB serialized review
  input. Both old and new contents count. Non-UTF-8/binary files, symlinks,
  submodules, exceeded limits, and unavailable Git objects explicitly block.
- The main agent has an eight-turn, ten-minute, ten-AI-credit limit, with no
  inference retries; threat detection is separately time-bounded. Copilot usage
  can be billable even though this is a public repository. Set account spending
  controls; the configured limits are not a guarantee of zero cost.
- **Rerun all jobs**, not only failed jobs, after repairing credentials or
  infrastructure. A partial rerun cannot reuse a previous attempt's approval.
- Hard cancellation or GitHub/runner/API unavailability can leave a pending or
  missing check. This blocks merging; it is not converted into success.
- Same-SHA rerun invalidation is event-driven, not atomic with the rerun click:
  GitHub must schedule the trusted lifecycle/start job. Do not merge while
  requesting a rerun; this scheduling window is a platform limitation.
- A base update requires an up-to-date branch and fresh review. Push a fresh
  commit or use **Update branch** before rerunning when the base has changed.

## Maintenance and local checks

Use Python 3.12+ (standard library only):

```shell
python -m unittest discover -s tests -v
gh aw compile security-compliance --gh-aw-ref 399a445fe2d8926c616b54b1b82a16b5b2be4445 --validate
```

Install the official `gh-aw` **v1.2.2** release before compiling; do not silently
upgrade the compiler. Commit both Markdown and regenerated YAML. The compiler
pins action/container dependencies; custom lifecycle checkout is also SHA-pinned.

All evaluator maintenance goes through a PR evaluated by the existing base
configuration. Review policy, workflow and adapter changes especially carefully.

## Honest security boundary

This is a **trusted-collaborator demo**, not tamper-proof enforcement against
repository administrators or privileged workflow authors. Administrators can
edit rules/settings. An Actions App-bound check does not uniquely identify one
workflow; another privileged workflow using that App could impersonate the name.
AI can miss issues or be influenced by adversarial text: green means a complete
review reported no violations, **not proof that the code is secure**. Production
hardening may need independently controlled required workflows/publishers and
mandatory security-owner reviews.

## References

- [Agentic Workflows custom safe outputs](https://github.github.io/gh-aw/reference/custom-safe-outputs/)
- [Copilot authentication](https://github.github.io/gh-aw/reference/auth/)
- [Trusted checkout and PR revisions](https://github.github.io/gh-aw/reference/checkout/)
- [Actions execution policies](https://docs.github.com/en/actions/how-tos/administer/control-workflow-execution)
- [Required status check semantics](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks)

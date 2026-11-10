# Copilot + Markdown policy gate

A public, dependency-free demonstration of a **required security-compliance
check**, not just an optional AI review comment. The standards are a fictional
[public sample](security/organization-standards.md), never confidential policy.

See the live demonstration links below for the current verdict on each exact
commit. A PR description or a green operational job is not a compliance verdict.

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
The additional native **Policy review completion** check must also succeed; it
runs even when dependencies fail or are skipped. Before inference, a read-only
preflight verifies that this exact attempt established its new pending check.

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
   also require `Policy review completion` from that App, strict up-to-date
   branches, no force push/deletion, **no bypasses**.
   Never disable protection to perform routine maintenance.

This personal repository does not assume organization-billed
`copilot-requests: write`. A secret name existing does not prove the PAT has a
valid entitlement; the actual inference run must succeed.

For **this repository**, setup is already active: the
[main ruleset](https://github.com/ShawnMcGough/copilot-policy-gate-demo/rules/26989916)
has an empty bypass list and both required checks bound to the observed GitHub
Actions App ID **15368**. The scoped
[Actions event policy](https://github.com/ShawnMcGough/copilot-policy-gate-demo/settings/actions/rules/12942)
is active. Real Copilot inference succeeded with the configured repository
secret; the owner only needs to maintain its entitlement, expiry and spending
controls. An owner's harmless empty direct push was rejected with `GH013`.

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

| Demonstration | Live evidence |
| --- | --- |
| Safe parameter binding | [PR #1](https://github.com/ShawnMcGough/copilot-policy-gate-demo/pull/1) |
| Unsafe SQL plus proposed policy weakening | [PR #4](https://github.com/ShawnMcGough/copilot-policy-gate-demo/pull/4) |
| Unsafe-to-corrected sequence | [PR #5](https://github.com/ShawnMcGough/copilot-policy-gate-demo/pull/5) |
| Provider/model error correctly blocked | [Initial run](https://github.com/ShawnMcGough/copilot-policy-gate-demo/actions/runs/42911479190) |
| Extra no-op output correctly rejected | [Output-contract run](https://github.com/ShawnMcGough/copilot-policy-gate-demo/actions/runs/42912960211) |
| Base policy applied despite proposed weakening | [Actual SEC-001 findings](https://github.com/ShawnMcGough/copilot-policy-gate-demo/actions/runs/42913533578) |
| Same-SHA agent-only rerun blocked before inference; full rerun recovered | [Safe run attempt history](https://github.com/ShawnMcGough/copilot-policy-gate-demo/actions/runs/42915214528) |
| Corrected latest head passed after a rapid superseding commit | [Corrected run history](https://github.com/ShawnMcGough/copilot-policy-gate-demo/actions/runs/42916638580) |
| Superseded review cancelled, never approved | [Cancelled older run](https://github.com/ShawnMcGough/copilot-policy-gate-demo/actions/runs/42916635829) |

Use the latest required checks, not an earlier green run. The provider-error run
used a retired model; the workflow now pins the advertised `claude-haiku-5.5`
model through **Copilot**, not a separate Anthropic credential. Optional no-op
output is disabled; it is not accepted as a compliance result.

Live observations on November 10, 2026 included `CLEAN` merge eligibility for
safe/corrected revisions and `BLOCKED` for SEC-001 violations. Full, agent-only,
and conclusion-only same-SHA rerun probes reported `BLOCKED` immediately after
the rerun request, even while raw check records still showed earlier successes.
The agent-only partial rerun failed before inference; a complete rerun restored
green. Run histories include intentional failures and cancellations.

The focused local tests cover malformed/incomplete evidence, fork rejection,
revision/attempt binding, docs/renames/deletions, base-policy selection and
unsupported content/limits. These are deterministic tests, not claims that an
outside-fork or every unsupported-file case was exercised live.

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
- Custom same-SHA rerun invalidation is event-driven, not atomic with the rerun click:
  GitHub must schedule the trusted lifecycle/start job. Do not merge while
  requesting a rerun. The native completion check is an additional safeguard,
  and the live rerun probes were blocked, but those observations do not establish
  a transactional guarantee for every scheduling/API race. **Strict atomic rerun
  invalidation remains an unproven acceptance requirement**, not an approved
  exception or a guarantee claimed by this demonstration.
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

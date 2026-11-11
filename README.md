# Copilot + Markdown security policy

One required check: **Organization Security Standard**.
GitHub Copilot reviews PR changes against a fictional
[public Markdown policy](security/organization-standards.md). Violations make the
Actions job fail and block merging into protected `main`.

## How it works

The ordinary [Actions workflow](.github/workflows/security-compliance.yml) has
**one job**, with sequential steps:

1. Read the policy from the PR's trusted **base commit** and collect the PR diff
   with surrounding context. Proposed policy edits do not change this review.
2. Run the official `@github/copilot` CLI with `claude-haiku-5.5`, using the existing
   `COPILOT_GITHUB_TOKEN` secret. PR files are data: never checked out, installed,
   or executed. Copilot has no tools and loads no repository instructions.
3. Validate Copilot's JSON response with a small inline `jq` check. Show findings
   and fixes in the job summary/log, then fail for any violation, incomplete
   review, missing/malformed result, or CLI error.

CLI exit code zero alone is **not** compliance. A passing job requires a valid,
complete report with zero violations. The CLI's `--output-format json` is an
event stream, not a policy verdict: `jq` extracts and validates the single
assistant response after a clean CLI completion. There is no built-in
fail-on-policy flag.

Steps appear inside the job's **Details**, not as separate PR checks. There is no
`gate.py`, generated workflow, lifecycle workflow, or custom Checks API publisher.
The native job conclusion is the required check.

## Try the demo

Open a same-repository PR targeting `main`, then open **Checks > Organization
Security Standard > Details** and its job summary.

- Use parameterized SQL: pass.
- Replace parameter binding with SQL string interpolation: fail **SEC-001**, with
  the file/line, explanation, and a concrete fix.
- Restore parameter binding and push a new commit: receive a fresh review.
- Propose weaker policy alongside unsafe SQL: the base policy still applies.

Existing demo PRs: [#4, unsafe SQL plus a proposed weaker policy](https://github.com/ShawnMcGough/copilot-policy-gate-demo/pull/4)
and [#5, corrected SQL](https://github.com/ShawnMcGough/copilot-policy-gate-demo/pull/5).
Their old runs demonstrate the previous implementation, not the new one-check UI.

## Setup

1. Use a Copilot-enabled account and save a fine-grained PAT with **Account
   permissions > Copilot Requests: Read** as the Actions secret
   `COPILOT_GITHUB_TOKEN`. This personal-account demo does not use
   organization-billed `GITHUB_TOKEN` inference or a separate model-provider key.
2. After a genuine run, require **Organization Security Standard** from the
   observed GitHub Actions App (**15368** here) in the `main` ruleset. Keep PRs
   required, strict up-to-date checks, no force push/deletion, and no bypasses.
3. Use trusted same-repository collaborators only. Fork PRs fail before
   credentialed analysis; the required job is not skipped to green.

The repository secret and protected `main` already exist. Keep the token's
entitlement, expiry, and spending controls current. The job has a ten-minute
timeout and a thirty-AI-credit CLI limit; usage can still be billable.

### Activating this revision

Until [PR #1](https://github.com/ShawnMcGough/copilot-policy-gate-demo/pull/1) is
merged, `main` still runs the old `pull_request_target`/lifecycle workflows, so
transitional PRs show their extra checks alongside this new job. Its singular
name avoids a collision with the old plural custom check. Historical checks do
not disappear.

With owner authorization, merge PR #1 **through the existing protections** after
the current required checks pass. Then edit
[ruleset 26989916](https://github.com/ShawnMcGough/copilot-policy-gate-demo/rules/26989916):
atomically replace **both** old required contexts (**Organization Security
Standards** and **Policy review completion**) with the verified native
**Organization Security Standard** from App 15368. Preserve all other rules,
strict up-to-date checks, and the empty bypass list.
The old scoped
[Actions event policy 12942](https://github.com/ShawnMcGough/copilot-policy-gate-demo/settings/actions/rules/12942)
can then be removed: this workflow uses `pull_request`, not `pull_request_target`.
Do not disable protection or add a bypass to perform the transition.

Update the demo branches to the new `main` while retaining their unsafe/corrected
examples, and push fresh revisions to verify the final one-check presentation.
Until that transition is authorized and completed, do not claim the new UI is
deployed repository-wide.

## Deliberate limits

This is a small **trusted-collaborator demo**, not production-grade enforcement.
`pull_request` uses the PR's workflow definition: a collaborator who can change
workflows can change the evaluator. Administrators can change protections, and
another workflow can use the same check name. Review workflow/policy changes
carefully; this is not tamper-proof enforcement against those actors.

Copilot can miss issues or be influenced by adversarial text. Green means a
complete review reported no violations, not proof of secure code. Large or
unsupported diffs may fail or need a smaller PR. There is no custom atomic
rerun-invalidation mechanism; use fresh commits for the demo and the latest
required result. After fixing credentials or infrastructure, rerun the job.

## References

- [Official direct CLI Actions example](https://docs.github.com/en/copilot/how-tos/copilot-cli/use-copilot-cli-in-actions)
- [Required status check semantics](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks)

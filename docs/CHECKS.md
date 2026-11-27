# Check reference

Every check returns either no findings (pass), findings (fail), or a skip with a
reason. The evidence field always quotes the value read from the API or the file,
so a finding can be verified by hand without trusting this tool.

## Repository checks

### R001 secret_scanning — high
Reads `security_and_analysis.secret_scanning.status` from the repository object.
Fails unless the value is `enabled`. Requires admin on the repository; otherwise
skipped with `security settings need admin on the repository`.

### R002 push_protection — high
Reads `security_and_analysis.secret_scanning_push_protection.status`. Push
protection is what stops a credential landing in the first place; scanning alone
detects it afterwards.

### R003 dependabot_alerts — medium
`GET /repos/{repo}/vulnerability-alerts` returns 204 when enabled and 404 when
not. The endpoint requires admin, so a 403 is recorded as skipped.

### R004 workflow_token — high
`GET /repos/{repo}/actions/permissions/workflow`. Fails when
`default_workflow_permissions` is `write`, which makes every workflow a
write-capable actor by default.

### R005 branch_protection — medium
`GET /repos/{repo}/branches/{default}/protection`. A 404 means no rule exists.
A 403 means the token cannot see the rule and is recorded as skipped, not as
protected.

### R006 security_policy — medium
Looks for `SECURITY.md`, `.github/SECURITY.md` or `docs/SECURITY.md` in the tree.
Public, non-archived repositories only.

### R007 licence — low
Reads `license` from the repository object. Public repositories only.

### R008 codeowners — low
Looks for `CODEOWNERS`, `.github/CODEOWNERS` or `docs/CODEOWNERS`.

### R009 ci — medium
Fails when a public, non-archived repository has no workflow under
`.github/workflows/`.

### R010 empty_repo — low
Fails when a public repository has no files on its default branch.

## Workflow checks

These read the workflow files themselves, so they work on any public repository
without special permission.

### W001 action_pinning — medium
Every `uses:` value must end in a 40-character commit SHA. Tags and branches are
mutable: a tag can be repointed at a new commit after review. `docker://` images
must be pinned by digest (`@sha256:`). Local actions (`./path`) are skipped.

### W002 pr_target_checkout — critical
`pull_request_target` runs with the base repository's token and secrets. If a
checkout step points at `github.event.pull_request.head.sha` or `github.head_ref`,
untrusted code executes with that privilege. This is the pwn-request pattern and
the highest-severity finding the tool can produce.

### W003 pr_target_secrets — high
Any `secrets.` reference inside a `pull_request_target` workflow. Not always
exploitable, always worth a review.

### W004 workflow_permissions — medium
Counts workflows with no top-level `permissions:` key. Without one the workflow
inherits the repository default, which may be write.

### W005 write_permissions — high, medium at job level
`permissions: write-all`, or any scope set to `write`. Workflow-level write is
**high** because it applies to every job in the file; job-level write is
**medium** because it is scoped and sometimes the only way to publish. The
evidence string names the scope, so the difference is visible in the report.

### W006 remote_script — high
A line that pipes `curl` or `wget` into `sh`, `bash`, `zsh` or `ksh`.

### W007 script_injection — high
A `run:` block that interpolates `github.event.*`, `github.head_ref` or
`inputs.*` directly into the shell. Values become command arguments; quoting does
not fix it, an environment variable does.

### W008 self_hosted_public — high
A job with `runs-on: self-hosted` in a public repository. Public PRs must not
execute on private infrastructure.

### W009 workflow_parse — medium
The file could not be parsed as YAML, so it was not reviewed. Reported rather
than ignored.

## Deliberately absent

- **History scanning.** Delegated to GitHub secret scanning (R001).
- **Branch protection policy depth.** R005 checks presence, not required
  reviewers or signed commits; those need admin and differ per team.
- **Runtime, cloud and identity posture.** Separate problem, separate tool.

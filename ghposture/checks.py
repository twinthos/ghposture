"""Check implementations.

Every check is a pure function of a RepoContext. A check that cannot run
because of missing permission must call ctx.skip(...) and return no findings:
silence is never evidence of safety.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from . import workflows
from .api import Forbidden, GitHub, NotFound
from .models import Finding, Severity

Findings = list[Finding]


@dataclass
class RepoContext:
    gh: GitHub
    meta: dict
    tree: list[str] = field(default_factory=list)
    workflow_text: dict[str, str] = field(default_factory=dict)
    workflow_doc: dict[str, Any] = field(default_factory=dict)
    parse_errors: dict[str, str] = field(default_factory=dict)
    skips: list[tuple[str, str]] = field(default_factory=list)
    _cache: dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.meta.get("name", "?")

    @property
    def full_name(self) -> str:
        return self.meta.get("full_name", self.name)

    @property
    def private(self) -> bool:
        return bool(self.meta.get("private"))

    @property
    def archived(self) -> bool:
        return bool(self.meta.get("archived"))

    @property
    def branch(self) -> str:
        return self.meta.get("default_branch") or "main"

    def skip(self, reason: str) -> None:
        if reason not in [r for _, r in self.skips]:
            self.skips.append((self.name, reason))

    def has(self, path: str) -> bool:
        lowered = path.lower()
        return any(p.lower() == lowered for p in self.tree)

    def find(self, *candidates: str) -> str | None:
        lowered = [c.lower() for c in candidates]
        for path in self.tree:
            if path.lower() in lowered:
                return path
        return None


def build_context(gh: GitHub, meta: dict) -> RepoContext:
    ctx = RepoContext(gh=gh, meta=meta)
    full = meta["full_name"]
    try:
        tree = gh.get(f"/repos/{full}/git/trees/{ctx.branch}?recursive=1")
        ctx.tree = [item["path"] for item in tree.get("tree", []) if "path" in item]
    except (NotFound, Forbidden):
        ctx.skip("repository tree unavailable")
        return ctx
    paths = [p for p in ctx.tree
             if p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml"))]
    for path in paths:
        try:
            blob = gh.get(f"/repos/{full}/contents/{path}?ref={ctx.branch}")
            import base64
            text = base64.b64decode(blob.get("content", "")).decode("utf-8", "replace")
        except (NotFound, Forbidden, KeyError):
            ctx.parse_errors[path] = "content unavailable"
            continue
        ctx.workflow_text[path] = text
        try:
            ctx.workflow_doc[path] = workflows.parse(text)
        except workflows.WorkflowError as exc:
            ctx.parse_errors[path] = str(exc)
    return ctx


def _finding(ctx: RepoContext, check: str, sev: Severity, title: str,
             evidence: str, remediation: str, location: str = "") -> Finding:
    return Finding(check=check, repo=ctx.full_name, severity=sev, title=title,
                   evidence=evidence, remediation=remediation, location=location)


# ----------------------------------------------------------------- repo state
def secret_scanning(ctx: RepoContext) -> Findings:
    analysis = ctx.meta.get("security_and_analysis")
    if not analysis:
        ctx.skip("security settings need admin on the repository")
        return []
    state = (analysis.get("secret_scanning") or {}).get("status")
    if state == "enabled":
        return []
    return [_finding(ctx, "R001", Severity.HIGH, "Secret scanning is off",
                     f"secret_scanning={state or 'disabled'}",
                     "Settings, Code security, enable secret scanning. Free on public repos.")]


def push_protection(ctx: RepoContext) -> Findings:
    analysis = ctx.meta.get("security_and_analysis")
    if not analysis:
        ctx.skip("security settings need admin on the repository")
        return []
    state = (analysis.get("secret_scanning_push_protection") or {}).get("status")
    if state == "enabled":
        return []
    return [_finding(ctx, "R002", Severity.HIGH, "Push protection is off",
                     f"push_protection={state or 'disabled'}",
                     "Enable push protection so a token is blocked before it lands.")]


def dependabot_alerts(ctx: RepoContext) -> Findings:
    """204 means enabled, 404 means disabled. Requires admin to read."""
    full = ctx.full_name
    try:
        code = ctx.gh.status(f"/repos/{full}/vulnerability-alerts")
    except Forbidden:
        ctx.skip("dependency alerts need admin on the repository")
        return []
    except NotFound:
        code = 404
    if code == 204:
        return []
    return [_finding(ctx, "R003", Severity.MEDIUM, "Dependabot alerts are off",
                     "vulnerability alerts endpoint returned 404",
                     "Settings, Code security, enable Dependabot alerts.")]


def workflow_permissions(ctx: RepoContext) -> Findings:
    full = ctx.full_name
    try:
        perms = ctx.gh.get(f"/repos/{full}/actions/permissions/workflow")
    except Forbidden:
        ctx.skip("Actions permissions need admin on the repository")
        return []
    except NotFound:
        ctx.skip("Actions permissions unavailable")
        return []
    if perms.get("default_workflow_permissions") == "write":
        return [_finding(ctx, "R004", Severity.HIGH, "Default workflow token can write",
                         "default_workflow_permissions=write",
                         "Set the default GITHUB_TOKEN permission to read in Actions settings.")]
    return []


def branch_protection(ctx: RepoContext) -> Findings:
    full, branch = ctx.full_name, ctx.branch
    try:
        ctx.gh.get(f"/repos/{full}/branches/{branch}/protection")
        return []
    except Forbidden:
        ctx.skip("branch protection needs admin on the repository")
        return []
    except NotFound:
        pass
    return [_finding(ctx, "R005", Severity.MEDIUM, f"Default branch '{branch}' is unprotected",
                     "no branch protection rule",
                     "Require a pull request and a passing check before merge.")]


def security_policy(ctx: RepoContext) -> Findings:
    if ctx.private or ctx.archived:
        return []
    if ctx.find("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"):
        return []
    return [_finding(ctx, "R006", Severity.MEDIUM, "No SECURITY.md",
                     "no security policy in the repository",
                     "Add SECURITY.md with a private reporting route and a response window.")]


def licence(ctx: RepoContext) -> Findings:
    if ctx.private:
        return []
    if ctx.meta.get("license"):
        return []
    return [_finding(ctx, "R007", Severity.LOW, "No licence",
                     "license=null",
                     "Add a licence so reuse terms are unambiguous.")]


def codeowners(ctx: RepoContext) -> Findings:
    if ctx.private or ctx.archived:
        return []
    if ctx.find("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"):
        return []
    return [_finding(ctx, "R008", Severity.LOW, "No CODEOWNERS",
                     "no CODEOWNERS file",
                     "Name a reviewer so ownership is explicit, not assumed.")]


def has_ci(ctx: RepoContext) -> Findings:
    if ctx.private or ctx.archived:
        return []
    if ctx.workflow_text:
        return []
    return [_finding(ctx, "R009", Severity.MEDIUM, "No CI workflow",
                     "no workflow under .github/workflows",
                     "Add a test workflow that runs on every pull request.")]


def empty_public_repo(ctx: RepoContext) -> Findings:
    if ctx.private or ctx.archived or ctx.tree:
        return []
    return [_finding(ctx, "R010", Severity.LOW, "Empty public repository",
                     "no files on the default branch",
                     "Make it private or populate it: an empty public repo is a loose end.")]


# ------------------------------------------------------------------- workflows
def unpinned_actions(ctx: RepoContext) -> Findings:
    out: Findings = []
    seen: set[str] = set()
    for path, doc in ctx.workflow_doc.items():
        for _, _, ref in workflows.action_refs(doc):
            if workflows.is_pinned(ref) or ref in seen:
                continue
            seen.add(ref)
            out.append(_finding(ctx, "W001", Severity.MEDIUM,
                                f"Action pinned to a mutable ref: {ref}",
                                f"{path}: {ref}", "Pin to a 40-character commit SHA.",
                                location=path))
    return out


def pr_target_head_checkout(ctx: RepoContext) -> Findings:
    out: Findings = []
    for path, doc in ctx.workflow_doc.items():
        if workflows.has_pr_target(doc) and workflows.checkouts_pr_head(doc):
            out.append(_finding(ctx, "W002", Severity.CRITICAL,
                                "pull_request_target checks out untrusted code",
                                f"{path}: PR head checked out under a privileged trigger",
                                "Run untrusted code in pull_request, not pull_request_target.",
                                location=path))
    return out


def pr_target_with_secrets(ctx: RepoContext) -> Findings:
    out: Findings = []
    for path, doc in ctx.workflow_doc.items():
        if workflows.has_pr_target(doc) and workflows.uses_secrets(ctx.workflow_text[path]):
            out.append(_finding(ctx, "W003", Severity.HIGH,
                                "pull_request_target workflow can read secrets",
                                f"{path}: secrets referenced under a privileged trigger",
                                "Remove secret access from PR-triggered workflows, or gate on approval.",
                                location=path))
    return out


def missing_permissions(ctx: RepoContext) -> Findings:
    offenders = sorted(p for p, d in ctx.workflow_doc.items()
                       if workflows.top_level_permissions(d) is None)
    if not offenders:
        return []
    return [_finding(ctx, "W004", Severity.MEDIUM,
                     f"{len(offenders)} workflow(s) set no permissions block",
                     ", ".join(offenders[:6]) + (" ..." if len(offenders) > 6 else ""),
                     "Add an explicit read-only permissions block to each workflow.")]


def write_permissions(ctx: RepoContext) -> Findings:
    out: Findings = []
    for path, doc in ctx.workflow_doc.items():
        for scope, value in workflows.workflow_permissions_matrix(doc):
            if workflows.permission_is_write_all(value):
                out.append(_finding(ctx, "W005", Severity.HIGH,
                                    "Workflow requests write permissions",
                                    f"{path}: {scope} permissions={value}",
                                    "Grant the narrowest scope the job needs.",
                                    location=path))
    return out


def remote_script(ctx: RepoContext) -> Findings:
    out: Findings = []
    for path, text in ctx.workflow_text.items():
        for line in workflows.remote_pipe_to_shell(text):
            out.append(_finding(ctx, "W006", Severity.HIGH,
                                "Remote script piped into a shell",
                                f"{path}:{line} curl or wget piped to sh",
                                "Download, verify a checksum or signature, then execute.",
                                location=path))
    return out


def script_injection(ctx: RepoContext) -> Findings:
    out: Findings = []
    for path, doc in ctx.workflow_doc.items():
        for job, index in workflows.script_injection_sites(doc):
            out.append(_finding(ctx, "W007", Severity.HIGH,
                                "Attacker-controlled context interpolated into a shell",
                                f"{path}: job {job} step {index}",
                                "Pass the value through an env var and quote it, or use an action input.",
                                location=path))
    return out


def self_hosted_runner(ctx: RepoContext) -> Findings:
    if ctx.private:
        return []
    out: Findings = []
    for path, doc in ctx.workflow_doc.items():
        for job in workflows.self_hosted(doc):
            out.append(_finding(ctx, "W008", Severity.HIGH,
                                "Self-hosted runner on a public repository",
                                f"{path}: job {job}",
                                "Do not run public-repo jobs on self-hosted infrastructure.",
                                location=path))
    return out


def unparsed_workflow(ctx: RepoContext) -> Findings:
    out: Findings = []
    for path, reason in sorted(ctx.parse_errors.items()):
        out.append(_finding(ctx, "W009", Severity.MEDIUM,
                            "Workflow could not be parsed",
                            f"{path}: {reason}",
                            "Fix the YAML so the workflow can be reviewed.",
                            location=path))
    return out


@dataclass(frozen=True)
class Check:
    id: str
    name: str
    description: str
    severity: Severity
    fn: Callable[[RepoContext], Findings]


REGISTRY: tuple[Check, ...] = (
    Check("R001", "secret_scanning", "GitHub secret scanning is enabled", Severity.HIGH, secret_scanning),
    Check("R002", "push_protection", "Push protection blocks new secrets", Severity.HIGH, push_protection),
    Check("R003", "dependabot_alerts", "Dependency alerts are enabled", Severity.MEDIUM, dependabot_alerts),
    Check("R004", "workflow_token", "Default workflow token is read-only", Severity.HIGH, workflow_permissions),
    Check("R005", "branch_protection", "Default branch is protected", Severity.MEDIUM, branch_protection),
    Check("R006", "security_policy", "SECURITY.md exists", Severity.MEDIUM, security_policy),
    Check("R007", "licence", "Licence declared", Severity.LOW, licence),
    Check("R008", "codeowners", "CODEOWNERS names a reviewer", Severity.LOW, codeowners),
    Check("R009", "ci", "CI runs on pull requests", Severity.MEDIUM, has_ci),
    Check("R010", "empty_repo", "Public repository is not empty", Severity.LOW, empty_public_repo),
    Check("W001", "action_pinning", "Actions pinned to commit SHAs", Severity.MEDIUM, unpinned_actions),
    Check("W002", "pr_target_checkout", "No untrusted checkout under pull_request_target",
          Severity.CRITICAL, pr_target_head_checkout),
    Check("W003", "pr_target_secrets", "No secrets under pull_request_target", Severity.HIGH, pr_target_with_secrets),
    Check("W004", "workflow_permissions", "Every workflow sets permissions", Severity.MEDIUM, missing_permissions),
    Check("W005", "write_permissions", "No workflow requests write access", Severity.HIGH, write_permissions),
    Check("W006", "remote_script", "No curl piped to shell", Severity.HIGH, remote_script),
    Check("W007", "script_injection", "No context interpolation in run blocks", Severity.HIGH, script_injection),
    Check("W008", "self_hosted_public", "No self-hosted runner on a public repo", Severity.HIGH, self_hosted_runner),
    Check("W009", "workflow_parse", "Every workflow parses", Severity.MEDIUM, unparsed_workflow),
)

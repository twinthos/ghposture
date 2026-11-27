from fakegh import FakeGitHub

from ghposture import checks
from ghposture.models import Severity


def ctx_for(meta, workflow_text, files=None):
    files = files or {}
    gh = FakeGitHub(meta, files=files)
    return checks.build_context(gh, meta)


def test_unpinned_actions_reported(meta, workflow_text):
    ctx = ctx_for(dict(meta), {"a": "bad"})
    ctx.workflow_text = {"a.yml": workflow_text("bad_pin.yml")}
    ctx.workflow_doc = {"a.yml": __import__("ghposture.workflows", fromlist=["x"]).parse(ctx.workflow_text["a.yml"])}
    findings = checks.unpinned_actions(ctx)
    assert len(findings) == 2  # tag-pinned action and tag-pinned container
    assert {f.severity for f in findings} == {Severity.MEDIUM}
    assert any("actions/checkout@v4" in f.title for f in findings)
    assert any("docker://alpine:3.20" in f.title for f in findings)


def test_pr_target_critical(meta, workflow_text):
    from ghposture import workflows
    doc = workflows.parse(workflow_text("pr_target.yml"))
    ctx = checks.RepoContext(gh=None, meta=meta,
                             workflow_text={"w.yml": workflow_text("pr_target.yml")},
                             workflow_doc={"w.yml": doc})
    assert [f.severity for f in checks.pr_target_head_checkout(ctx)] == [Severity.CRITICAL]
    assert len(checks.pr_target_with_secrets(ctx)) == 1


def test_clean_workflow_has_no_workflow_findings(meta, workflow_text):
    from ghposture import workflows
    doc = workflows.parse(workflow_text("good.yml"))
    ctx = checks.RepoContext(gh=None, meta=meta,
                             workflow_text={"w.yml": workflow_text("good.yml")},
                             workflow_doc={"w.yml": doc})
    for fn in (checks.unpinned_actions, checks.pr_target_head_checkout,
               checks.pr_target_with_secrets, checks.missing_permissions,
               checks.write_permissions, checks.remote_script,
               checks.script_injection, checks.self_hosted_runner,
               checks.unparsed_workflow):
        assert fn(ctx) == [], fn.__name__


def test_missing_admin_degrades_to_skip(meta):
    meta = dict(meta)
    meta.pop("security_and_analysis")
    ctx = checks.RepoContext(gh=None, meta=meta)
    assert checks.secret_scanning(ctx) == []
    assert ctx.skips
    assert "admin" in ctx.skips[0][1]


def test_public_repo_hygiene(meta):
    ctx = checks.RepoContext(gh=None, meta=meta, tree=["README.md"])
    assert checks.security_policy(ctx)[0].check == "R006"
    assert checks.codeowners(ctx)[0].check == "R008"
    assert checks.has_ci(ctx)[0].check == "R009"
    empty = checks.RepoContext(gh=None, meta=meta, tree=[])
    assert checks.empty_public_repo(empty)[0].check == "R010"


def test_private_repo_skips_public_hygiene(meta):
    ctx = checks.RepoContext(gh=None, meta={**meta, "private": True}, tree=[])
    assert checks.security_policy(ctx) == []
    assert checks.has_ci(ctx) == []


def test_dependabot_422_is_not_applicable(meta):
    from ghposture.api import Unprocessable

    class NoGraph:
        def status(self, path):
            raise Unprocessable("no graph")

    ctx = checks.RepoContext(gh=NoGraph(), meta=meta)
    assert checks.dependabot_alerts(ctx) == []
    assert any("dependency graph" in reason for _, reason in ctx.skips)


def test_write_permission_severity_depends_on_scope(meta, workflow_text):
    from ghposture import workflows
    doc = workflows.parse(workflow_text("write_all.yml"))
    ctx = checks.RepoContext(gh=None, meta=meta,
                             workflow_text={"w.yml": workflow_text("write_all.yml")},
                             workflow_doc={"w.yml": doc})
    findings = checks.write_permissions(ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH

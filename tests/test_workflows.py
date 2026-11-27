import pytest

from ghposture import workflows


def test_on_key_is_not_boolean(workflow_text):
    doc = workflows.parse(workflow_text("good.yml"))
    assert workflows.triggers(doc) == {"pull_request"}


def test_parse_rejects_broken_yaml(workflow_text):
    with pytest.raises(workflows.WorkflowError):
        workflows.parse(workflow_text("broken.yml"))


@pytest.mark.parametrize("ref,expected", [
    ("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", True),
    ("actions/checkout@v4", False),
    ("actions/checkout@main", False),
    ("actions/checkout", False),
    ("docker://alpine:3.20", False),
    ("docker://alpine@sha256:" + "a" * 64, True),
])
def test_pinning(ref, expected):
    assert workflows.is_pinned(ref) is expected


def test_action_refs_skips_local(workflow_text):
    doc = workflows.parse(workflow_text("bad_pin.yml"))
    refs = [ref for _, _, ref in workflows.action_refs(doc)]
    assert "actions/checkout@v4" in refs
    assert not any(r.startswith("./") for r in refs)


def test_pr_target_checkout_detected(workflow_text):
    doc = workflows.parse(workflow_text("pr_target.yml"))
    assert workflows.has_pr_target(doc)
    assert workflows.checkouts_pr_head(doc)


def test_good_workflow_is_not_pr_target(workflow_text):
    doc = workflows.parse(workflow_text("good.yml"))
    assert not workflows.has_pr_target(doc)
    assert not workflows.checkouts_pr_head(doc)


def test_injection_and_pipe_detected(workflow_text):
    text = workflow_text("injection.yml")
    doc = workflows.parse(text)
    assert workflows.script_injection_sites(doc)
    assert workflows.remote_pipe_to_shell(text)


def test_self_hosted(workflow_text):
    doc = workflows.parse(workflow_text("injection.yml"))
    assert workflows.self_hosted(doc) == ["build"]


def test_write_all(workflow_text):
    doc = workflows.parse(workflow_text("write_all.yml"))
    assert workflows.top_level_permissions(doc) == "write-all"
    assert workflows.permission_is_write_all("write-all")
    assert workflows.permission_is_write_all({"contents": "write"})
    assert not workflows.permission_is_write_all({"contents": "read"})

"""Static analysis of GitHub Actions workflow files.

PyYAML is the only third-party dependency in this tool. Hand-rolled YAML is
not an option: workflow files contain anchors, multi-line scalars and
expressions that a regex reader mis-parses, and a scanner that mis-parses
workflows produces false assurance.

YAML 1.1 pitfall handled here: the key `on:` parses as boolean True.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

import yaml

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^\s'\"]+)")
CURL_PIPE_RE = re.compile(
    r"(?:curl|wget)[^\n|]*\|[^\n]*(?:ba|z|k)?sh\b", re.IGNORECASE)
INJECTION_RE = re.compile(
    r"\$\{\{\s*(?:github\.event\.[a-z_.]+|github\.head_ref|inputs\.[a-z_]+)\s*\}\}",
    re.IGNORECASE)
PR_HEAD_RE = re.compile(
    r"\$\{\{\s*github\.(?:event\.pull_request\.head\.(?:sha|ref)|head_ref)\s*\}\}")


class WorkflowError(ValueError):
    pass


def parse(text: str) -> dict[str, Any]:
    """Parse a workflow. Raises WorkflowError rather than guessing."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise WorkflowError(f"invalid YAML: {exc.__class__.__name__}") from None
    if not isinstance(doc, dict):
        raise WorkflowError("workflow is not a mapping")
    return _normalise_keys(doc)


def _normalise_keys(node: Any) -> Any:
    """YAML 1.1 turns `on` into True. Put it back."""
    if isinstance(node, dict):
        return {("on" if k is True else k): _normalise_keys(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_normalise_keys(v) for v in node]
    return node


def triggers(doc: dict) -> set[str]:
    raw = doc.get("on")
    if raw is None:
        return set()
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, list):
        return {str(x) for x in raw}
    if isinstance(raw, dict):
        return {str(k) for k in raw}
    return set()


def jobs(doc: dict) -> Iterator[tuple[str, dict]]:
    raw = doc.get("jobs")
    if not isinstance(raw, dict):
        return
    for name, job in raw.items():
        if isinstance(job, dict):
            yield str(name), job


def steps(doc: dict) -> Iterator[tuple[str, int, dict]]:
    for job_name, job in jobs(doc):
        raw = job.get("steps")
        if not isinstance(raw, list):
            continue
        for index, step in enumerate(raw):
            if isinstance(step, dict):
                yield job_name, index, step


def action_refs(doc: dict) -> list[tuple[str, int, str]]:
    """Every `uses:` value, with job and step index. Local actions skipped."""
    out = []
    for job_name, index, step in steps(doc):
        uses = step.get("uses")
        if isinstance(uses, str) and uses.startswith("./"):
            continue
        if isinstance(uses, str) and uses.strip():
            out.append((job_name, index, uses.strip()))
    return out


def action_refs_raw(text: str) -> list[tuple[int, str]]:
    """Line-level fallback, used when a file fails to parse."""
    out = []
    for number, line in enumerate(text.splitlines(), start=1):
        match = USES_RE.match(line)
        if match and not match.group(1).startswith("./"):
            out.append((number, match.group(1)))
    return out


def is_pinned(ref: str) -> bool:
    """A ref is pinned only when it names an immutable 40-character commit."""
    if ref.startswith("docker://"):
        return "@sha256:" in ref
    if "@" not in ref:
        return False
    return bool(SHA_RE.match(ref.rsplit("@", 1)[1].strip()))


def top_level_permissions(doc: dict) -> Any:
    return doc.get("permissions")


def permission_is_write_all(value: Any) -> bool:
    if value == "write-all":
        return True
    if isinstance(value, dict):
        return any(str(v).lower() == "write" for v in value.values())
    return False


def has_pr_target(doc: dict) -> bool:
    return "pull_request_target" in triggers(doc)


def checkouts_pr_head(doc: dict) -> bool:
    for _, _, step in steps(doc):
        uses = step.get("uses")
        if not isinstance(uses, str) or "checkout" not in uses:
            continue
        with_block = step.get("with") or {}
        for value in with_block.values() if isinstance(with_block, dict) else []:
            if isinstance(value, str) and PR_HEAD_RE.search(value):
                return True
    return False


def uses_secrets(text: str) -> bool:
    return "secrets." in text


def self_hosted(doc: dict) -> list[str]:
    out = []
    for job_name, job in jobs(doc):
        runs_on = job.get("runs-on")
        values = runs_on if isinstance(runs_on, list) else [runs_on]
        if any(isinstance(v, str) and "self-hosted" in v for v in values):
            out.append(job_name)
    return out


def remote_pipe_to_shell(text: str) -> list[int]:
    return [n for n, line in enumerate(text.splitlines(), start=1)
            if CURL_PIPE_RE.search(line)]


def script_injection_sites(doc: dict) -> list[tuple[str, int]]:
    """`run:` steps that interpolate attacker-influenced context directly into
    a shell, which allows argument injection (the classic pwn-request)."""
    out = []
    for job_name, index, step in steps(doc):
        run = step.get("run")
        if isinstance(run, str) and INJECTION_RE.search(run):
            out.append((job_name, index))
    return out


def workflow_permissions_matrix(doc: dict) -> list[tuple[str, Any]]:
    out = [("<top level>", doc.get("permissions"))]
    for job_name, job in jobs(doc):
        if "permissions" in job:
            out.append((job_name, job.get("permissions")))
    return out

"""Scan orchestration. One repository at a time, one check at a time."""
from __future__ import annotations

import datetime as dt
from collections.abc import Iterable

from . import __version__
from .api import ApiError, Forbidden, GitHub, NotFound
from .checks import REGISTRY, build_context
from .models import CheckResult, Report, Status


def list_repos(gh: GitHub, org: str | None, repos: Iterable[str] | None,
               include_private: bool = True) -> list[dict]:
    if repos:
        out = []
        for full_name in repos:
            out.append(gh.get(f"/repos/{full_name}"))
        return out
    if not org:
        raise ValueError("an organisation or a list of repos is required")
    try:
        discovered = gh.paginate(f"/orgs/{org}/repos", {"type": "all", "sort": "full_name"})
    except NotFound:
        discovered = []
    if not discovered:
        discovered = gh.paginate(f"/users/{org}/repos", {"type": "all", "sort": "full_name"})
    if not include_private:
        discovered = [r for r in discovered if not r.get("private")]
    return sorted(discovered, key=lambda r: r.get("full_name", ""))


def scan(gh: GitHub, org: str | None = None, repos: Iterable[str] | None = None,
         include_private: bool = True, now: dt.datetime | None = None) -> Report:
    now = now or dt.datetime.now(dt.timezone.utc)
    report = Report(target=org or ", ".join(sorted(repos or [])),
                    generated_at=now.replace(microsecond=0).isoformat(),
                    tool_version=__version__)
    for meta in list_repos(gh, org, repos, include_private):
        full_name = meta.get("full_name", "?")
        report.repos_scanned += 1
        try:
            ctx = build_context(gh, meta)
        except (ApiError, Forbidden, NotFound) as exc:
            report.repos_inaccessible.append((full_name, type(exc).__name__))
            continue
        for check in REGISTRY:
            try:
                findings = check.fn(ctx)
            except Forbidden:
                ctx.skip("permission denied")
                findings = []
            except NotFound:
                ctx.skip("resource not found")
                findings = []
            except ApiError as exc:
                ctx.skip(f"api error: {type(exc).__name__}")
                findings = []
            report.results.append(CheckResult(
                check=check.id, repo=full_name,
                status=Status.FAIL if findings else Status.PASS,
                detail=f"{len(findings)} finding(s)" if findings else ""))
            report.findings.extend(findings)
        for _, reason in ctx.skips:
            report.coverage.add_skipped(full_name, reason)
        for name in {c.id for c in REGISTRY} - {r.check for r in report.results if r.repo == full_name}:
            report.coverage.add_skipped(f"{full_name}:{name}", "not evaluated")
        report.coverage.add_checked(full_name)
    return report

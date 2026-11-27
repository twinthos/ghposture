"""Renderers. Same data, three shapes: text, markdown, json."""
from __future__ import annotations

import json

from .models import Report, Severity

ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
LABEL = {Severity.CRITICAL: "CRITICAL", Severity.HIGH: "HIGH", Severity.MEDIUM: "MEDIUM",
         Severity.LOW: "LOW", Severity.INFO: "INFO"}


def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)


def _headline(report: Report) -> list[str]:
    counts = report.counts()
    passed, applicable = report.pass_rate()
    return [
        f"target      {report.target}",
        f"repos       {report.repos_scanned}",
        f"generated   {report.generated_at}",
        f"risk points {report.risk_points}",
        f"checks      {passed}/{applicable} passed",
        "severity    " + "  ".join(f"{k}={counts[k]}" for k in
                                  ("critical", "high", "medium", "low")),
    ]


def to_text(report: Report, verbose: bool = False) -> str:
    lines = _headline(report) + [""]
    if not report.findings:
        lines.append("No findings. Coverage is listed below: read it before treating this as safe.")
    for f in sorted(report.findings, key=lambda f: f.sort_key()):
        mark = "accepted" if f.accepted else LABEL[f.severity]
        lines.append(f"[{mark}] {f.check} {f.repo}: {f.title}")
        if f.evidence:
            lines.append(f"         evidence: {f.evidence}")
        if f.remediation and (verbose or f.severity in (Severity.CRITICAL, Severity.HIGH)):
            lines.append(f"         fix: {f.remediation}")
        if f.accepted:
            lines.append(f"         accepted: {f.acceptance_reason}")
    lines.append("")
    lines.append("coverage")
    for name in report.coverage.checked:
        lines.append(f"  checked  {name}")
    for name, reason in report.coverage.skipped:
        lines.append(f"  skipped  {name}: {reason}")
    if report.repos_inaccessible:
        for name, reason in report.repos_inaccessible:
            lines.append(f"  error    {name}: {reason}")
    lines.append("")
    lines.append("Not covered: secret history scanning (GitHub secret scanning covers it when R001 passes),")
    lines.append("dependency contents, runtime configuration, and anything in private repos without admin.")
    return "\n".join(lines)


def to_markdown(report: Report) -> str:
    counts = report.counts()
    passed, applicable = report.pass_rate()
    out = [f"# GitHub posture: {report.target}", "",
           f"Generated {report.generated_at} by ghposture {report.tool_version}.", "",
           "| metric | value |", "|---|---|",
           f"| Repositories scanned | {report.repos_scanned} |",
           f"| Risk points | {report.risk_points} |",
           f"| Checks passed | {passed} of {applicable} |",
           f"| Critical | {counts['critical']} |", f"| High | {counts['high']} |",
           f"| Medium | {counts['medium']} |", f"| Low | {counts['low']} |", ""]
    if report.findings:
        out += ["## Findings", "", "| severity | check | repository | finding | fix |", "|---|---|---|---|---|"]
        for f in sorted(report.findings, key=lambda f: f.sort_key()):
            sev = "accepted" if f.accepted else LABEL[f.severity]
            out.append(f"| {sev} | {f.check} | `{f.repo}` | {f.title} | {f.remediation} |")
        out.append("")
    else:
        out += ["## Findings", "", "No findings within the coverage below.", ""]
    out += ["## Coverage", ""]
    for name in report.coverage.checked:
        out.append(f"- checked: `{name}`")
    for name, reason in report.coverage.skipped:
        out.append(f"- skipped: `{name}` ({reason})")
    out += ["", "Secret history scanning is delegated to GitHub secret scanning (check R001); "
            "the scanner does not clone history. Private repositories without admin are "
            "recorded as skipped, never as passing."]
    return "\n".join(out)

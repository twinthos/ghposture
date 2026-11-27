import json

from ghposture import report as report_mod
from ghposture.models import Finding, Report, Severity


def build():
    r = Report(target="twinthos", generated_at="2026-11-27T00:00:00+00:00", tool_version="1.0.0")
    r.repos_scanned = 2
    r.findings = [
        Finding("W001", "o/b", Severity.MEDIUM, "pin", "e", "m"),
        Finding("W002", "o/a", Severity.CRITICAL, "prt", "e", "m"),
    ]
    return r


def test_json_is_sorted_and_parses():
    payload = json.loads(report_mod.to_json(build()))
    assert payload["summary"]["by_severity"]["critical"] == 1
    assert [f["check"] for f in payload["findings"]] == ["W002", "W001"]
    assert payload["tool"] == "ghposture"


def test_markdown_has_findings_table():
    md = report_mod.to_markdown(build())
    assert "| CRITICAL | W002" in md
    assert "Risk points" in md


def test_text_names_coverage_limits():
    text = report_mod.to_text(build())
    assert "Not covered" in text
    assert "skipped" in text or "coverage" in text


def test_empty_report_does_not_claim_safety():
    empty = Report(target="x", generated_at="now", tool_version="1")
    text = report_mod.to_text(empty)
    assert "read it before treating this as safe" in text

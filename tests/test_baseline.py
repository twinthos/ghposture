import datetime as dt
import json

import pytest

from ghposture import baseline
from ghposture.models import Finding, Report, Severity


def make_report():
    r = Report(target="x", generated_at="2026-01-01T00:00:00+00:00", tool_version="1.0.0")
    r.findings.append(Finding(check="R001", repo="o/r", severity=Severity.HIGH,
                              title="t", evidence="e", remediation="m"))
    return r


def test_apply_marks_accepted():
    r = make_report()
    entry = baseline.Entry("o/r", "R001", "compensating control", "2999-01-01")
    baseline.apply(r, [entry], today=dt.date(2026, 1, 1))
    assert r.findings[0].accepted
    assert r.risk_points == 0


def test_expired_entry_does_not_suppress():
    r = make_report()
    entry = baseline.Entry("o/r", "R001", "old", "2020-01-01")
    baseline.apply(r, [entry], today=dt.date(2026, 1, 1))
    assert not r.findings[0].accepted
    assert r.risk_points == Severity.HIGH.weight


def test_load_rejects_missing_fields(tmp_path):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"accepted": [{"repo": "o/r"}]}))
    with pytest.raises(ValueError):
        baseline.load(p)

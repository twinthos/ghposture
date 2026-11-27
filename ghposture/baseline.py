"""Accepted risks with an expiry date.

A baseline entry suppresses a finding only until its date. There is no
"accept forever": a suppressed issue that nobody revisits is how estates rot.
"""
from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, replace
from pathlib import Path

from .models import Report


@dataclass(frozen=True)
class Entry:
    repo: str
    check: str
    reason: str
    expires: str

    def is_live(self, today: dt.date | None = None) -> bool:
        today = today or dt.date.today()
        try:
            return dt.date.fromisoformat(self.expires) >= today
        except ValueError:
            return False


def load(path: str | Path) -> list[Entry]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    raw = data.get("accepted", []) if isinstance(data, dict) else []
    entries: list[Entry] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        try:
            entries.append(Entry(str(item["repo"]), str(item["check"]),
                                 str(item.get("reason", "")), str(item["expires"])))
        except KeyError as exc:
            raise ValueError(f"baseline entry missing {exc}") from None
    return entries


def apply(report: Report, entries: list[Entry], today: dt.date | None = None) -> None:
    """Mark covered findings accepted. Findings are immutable, so the report's
    list is rebuilt rather than mutated in place."""
    live = {(e.repo.lower(), e.check): e for e in entries if e.is_live(today)}
    updated = []
    for finding in report.findings:
        entry = live.get((finding.repo.lower(), finding.check))
        if entry:
            finding = replace(finding, accepted=True, acceptance_reason=entry.reason)
        updated.append(finding)
    report.findings = updated

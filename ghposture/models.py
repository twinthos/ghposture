"""Core data types. No I/O, no network, no globals."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}[self.value]

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class Finding:
    """One failed check against one repository."""
    check: str
    repo: str
    severity: Severity
    title: str
    evidence: str
    remediation: str
    location: str = ""
    accepted: bool = False
    acceptance_reason: str = ""

    def sort_key(self) -> tuple:
        return (-self.severity.rank, self.repo, self.check, self.location)


@dataclass
class CheckResult:
    """Outcome of one check against one repository, pass or fail."""
    check: str
    repo: str
    status: Status
    detail: str = ""


@dataclass
class Coverage:
    """What was actually inspected. Published so a clean report cannot imply
    more assurance than the run earned."""
    checked: list[str] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)

    def add_checked(self, name: str) -> None:
        if name not in self.checked:
            self.checked.append(name)

    def add_skipped(self, name: str, reason: str) -> None:
        if (name, reason) not in self.skipped:
            self.skipped.append((name, reason))


@dataclass
class Report:
    target: str
    generated_at: str
    tool_version: str
    findings: list[Finding] = field(default_factory=list)
    results: list[CheckResult] = field(default_factory=list)
    coverage: Coverage = field(default_factory=Coverage)
    repos_scanned: int = 0
    repos_inaccessible: list[tuple[str, str]] = field(default_factory=list)

    @property
    def risk_points(self) -> int:
        return sum(f.severity.weight for f in self.findings if not f.accepted)

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            if not f.accepted:
                out[f.severity.value] += 1
        return out

    def pass_rate(self) -> tuple[int, int]:
        applicable = [r for r in self.results if r.status is not Status.SKIPPED]
        passed = [r for r in applicable if r.status is Status.PASS]
        return len(passed), len(applicable)

    def to_dict(self) -> dict[str, Any]:
        passed, applicable = self.pass_rate()
        return {
            "tool": "ghposture",
            "tool_version": self.tool_version,
            "target": self.target,
            "generated_at": self.generated_at,
            "repos_scanned": self.repos_scanned,
            "repos_inaccessible": [{"repo": r, "reason": w} for r, w in sorted(self.repos_inaccessible)],
            "summary": {
                "risk_points": self.risk_points,
                "by_severity": self.counts(),
                "checks_passed": passed,
                "checks_applicable": applicable,
                "findings_total": len([f for f in self.findings if not f.accepted]),
                "findings_accepted": len([f for f in self.findings if f.accepted]),
            },
            "coverage": {
                "checked": sorted(self.coverage.checked),
                "skipped": [{"check": c, "reason": r} for c, r in sorted(self.coverage.skipped)],
            },
            "findings": [asdict(f) for f in sorted(self.findings, key=Finding.sort_key)],
            "results": [
                {"check": r.check, "repo": r.repo,
                 "status": r.status.value, "detail": r.detail}
                for r in sorted(self.results, key=lambda r: (r.repo, r.check))
            ],
        }

"""Command line entry point.

    ghposture scan --org twinthos --format md --out report.md
    ghposture scan --repo twinthos/ghposture --format json
    ghposture checks

Exit codes: 0 clean, 1 findings at or above --fail-on, 2 usage or runtime error.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from . import baseline as baseline_mod
from . import report as report_mod
from .api import ApiError, Forbidden, GitHub, RateLimited
from .models import Severity
from .runner import scan

FAIL_LEVELS = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
               "medium": Severity.MEDIUM, "low": Severity.LOW, "none": Severity.INFO}


def _token() -> str:
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        value = os.environ.get(name)
        if value:
            return value
    raise SystemExit("set GITHUB_TOKEN or GH_TOKEN to a read-only token")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ghposture",
        description="Deterministic GitHub estate posture scanner. Read-only.")
    parser.add_argument("--version", action="version", version=f"ghposture {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="scan an organisation or a list of repositories")
    scan_p.add_argument("--org", help="organisation or user login")
    scan_p.add_argument("--repo", action="append", default=[], help="owner/name, repeatable")
    scan_p.add_argument("--public-only", action="store_true")
    scan_p.add_argument("--format", choices=("text", "md", "json"), default="text")
    scan_p.add_argument("--out", help="write to a file instead of stdout")
    scan_p.add_argument("--baseline", help="accepted risks file")
    scan_p.add_argument("--fail-on", choices=tuple(FAIL_LEVELS), default="high")
    scan_p.add_argument("--verbose", action="store_true")

    sub.add_parser("checks", help="list checks and exit")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "checks":
        from .checks import REGISTRY
        for check in REGISTRY:
            print(f"{check.id}  {check.severity.value:<8} {check.name:<24} {check.description}")
        return 0

    if not args.org and not args.repo:
        print("error: pass --org or --repo", file=sys.stderr)
        return 2
    try:
        gh = GitHub(_token())
        result = scan(gh, org=args.org, repos=args.repo or None,
                      include_private=not args.public_only)
        if args.baseline:
            baseline_mod.apply(result, baseline_mod.load(args.baseline))
    except RateLimited:
        print("error: rate limited by GitHub; retry after the reset window", file=sys.stderr)
        return 2
    except Forbidden:
        print("error: token lacks permission for this organisation", file=sys.stderr)
        return 2
    except (ApiError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    rendered = {"text": lambda r: report_mod.to_text(r, args.verbose),
                "md": report_mod.to_markdown,
                "json": report_mod.to_json}[args.format](result)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
        print(f"wrote {args.out}: {len(result.findings)} finding(s), "
              f"risk points {result.risk_points}")
    else:
        print(rendered)

    threshold = FAIL_LEVELS[args.fail_on]
    worst = max((f.severity.rank for f in result.findings if not f.accepted), default=0)
    return 1 if worst >= threshold.rank and args.fail_on != "none" else 0


if __name__ == "__main__":
    raise SystemExit(main())

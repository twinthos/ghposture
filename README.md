# ghposture

A read-only scanner for a GitHub estate. It answers one question with evidence: **which of my repositories are configured in a way an attacker can use, and which ones could not be checked at all.**

Deterministic output, no daemon, no database, no SaaS. Standard library plus PyYAML.

```
$ ghposture scan --org twinthos
target      twinthos
repos       13
risk points 33
checks      81/95 passed
severity    critical=0  high=0  medium=14  low=5

[HIGH] R002 twinthos/example: Push protection is off
       evidence: push_protection=disabled
       fix: Enable push protection so a token is blocked before it lands.
```

## Why this exists

Most repository "security scores" are a single number with no method behind it. This tool refuses that. Every finding carries the exact API value that produced it, every skipped check is published with the reason, and the output separates *checked and passed* from *could not check*. A clean report from a token without admin rights looks different from a clean report with full coverage, because the coverage section says so.

## Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m ghposture checks      # list the 19 checks
```

Requires Python 3.10 or newer.

## Use

```bash
export GITHUB_TOKEN=...            # read-only fine-grained token is enough for most checks
ghposture scan --org twinthos --format md --out report.md
ghposture scan --repo twinthos/ghposture --format json
ghposture scan --org twinthos --public-only --fail-on critical
ghposture scan --org twinthos --baseline .posture-baseline.json
```

| flag | meaning |
|---|---|
| `--org` | organisation or user login |
| `--repo` | `owner/name`, repeatable; skips discovery |
| `--public-only` | ignore private repositories |
| `--format` | `text`, `md`, `json` |
| `--out` | write to a file; the console gets a one-line summary |
| `--baseline` | accepted risks with expiry dates |
| `--fail-on` | `critical`, `high` (default), `medium`, `low`, `none` |

Exit codes: `0` clean at the chosen threshold, `1` findings at or above it, `2` usage or API failure.

### Token scope

Read the checks you can. Without admin on a repository, `security_and_analysis`, dependency alerts, Actions permissions and branch protection return 403 and are recorded as **skipped**, never as passed. A fine-grained token with `Administration: read`, `Contents: read` and `Actions: read` gives full coverage on repositories you own.

## The 19 checks

| id | check | severity | what a failure means |
|---|---|---|---|
| R001 | Secret scanning enabled | high | GitHub is not watching pushes for credentials |
| R002 | Push protection enabled | high | A token can be committed without being blocked |
| R003 | Dependency alerts enabled | medium | Known-vulnerable dependencies go unreported |
| R004 | Default workflow token read-only | high | Any workflow gets write access by default |
| R005 | Default branch protected | medium | Force-push and direct pushes are possible |
| R006 | SECURITY.md present | medium | No stated way to report a vulnerability |
| R007 | Licence declared | low | Reuse terms are ambiguous |
| R008 | CODEOWNERS present | low | Review ownership is assumed, not assigned |
| R009 | CI workflow present | medium | Nothing checks a change before merge |
| R010 | Public repository not empty | low | An empty public repo is an unowned surface |
| W001 | Actions pinned to commit SHAs | medium | A tag can be moved under you |
| W002 | No untrusted checkout under `pull_request_target` | critical | The classic pwn-request: PR code with a privileged token |
| W003 | No secrets under `pull_request_target` | high | Secrets reachable from a PR-triggered workflow |
| W004 | Every workflow sets `permissions` | medium | Token scope is whatever the default is |
| W005 | No workflow requests write access | high | A compromised step can write to the repo |
| W006 | No `curl … \| sh` | high | Remote code executes without verification |
| W007 | No context interpolation in `run:` | high | `${{ github.event.* }}` in a shell is command injection |
| W008 | No self-hosted runner on a public repo | high | Untrusted jobs run on your infrastructure |
| W009 | Every workflow parses | medium | An unreadable workflow is an unreviewed workflow |

Full semantics, including the exact evidence string for each, are in [docs/CHECKS.md](docs/CHECKS.md).

## Scoring

Risk points are `critical 10, high 5, medium 2, low 1, info 0`, summed over unaccepted findings. There is no 0–100 score and no letter grade, because those invent precision that a static scan does not have. Compare risk points across runs of the same target, not across organisations of different size.

Coverage is reported as `checks passed / checks applicable`. Skipped checks are excluded from the denominator and listed separately.

## Accepted risks

```json
{
  "accepted": [
    {
      "repo": "twinthos/twinthos-public-site",
      "check": "R005",
      "reason": "Deploy branch; protection adds force-push blocking but PR requirement breaks CI publishing",
      "expires": "2027-02-28"
    }
  ]
}
```

An entry suppresses a finding only until `expires`. There is no permanent acceptance: an exception nobody revisits is how estates rot. Expired entries are ignored and the finding returns.

## What this does not do

Stated plainly, because a scanner that hides its edges is worse than no scanner:

- **No git history scan.** Credential history is delegated to GitHub secret scanning, which is what R001 checks. Cloning every repository to re-implement it adds a large trust boundary for no extra signal.
- **No runtime or infrastructure review.** IAM, cloud posture and deployed configuration are out of scope.
- **No dependency contents analysis.** R003 checks that alerts are on; it does not read your lockfiles.
- **No exploitation.** Every check reads public metadata or files the token can already see. Nothing is probed.
- **No private repositories without permission.** They appear as skipped, with the reason.

## Design rules

1. **Skip is not pass.** Any check that cannot run is recorded as skipped with a reason.
2. **Evidence beats adjectives.** Every finding stores the exact value that triggered it.
3. **Deterministic output.** Sorted findings, sorted keys, no timestamps in comparisons.
4. **One dependency.** PyYAML, because regex-parsing workflow files produces confident nonsense. The YAML 1.1 `on:` key becomes boolean `True` and is normalised back — there is a test for it.
5. **Immutable findings.** Baseline application rebuilds the list rather than mutating records.
6. **No token in output.** The client never logs the token, and error text contains only status codes.

## Development

```bash
pip install -r requirements-dev.txt
pytest              # ................................ tests, no network
ruff check .
```

Tests use a fake REST client; no test touches the network. Workflow fixtures live in `tests/fixtures/`.

## Licence

Apache-2.0. See [LICENSE](LICENSE).

# Contributing

## The one rule

**Never let a check pass by accident.** If a check cannot run, it must call
`ctx.skip(reason)` and return no findings. A silent pass is the bug this project
exists to prevent, and it is the only thing treated as urgent.

## Before you open a pull request

```bash
pip install -r requirements-dev.txt
pytest
ruff check .
```

Both must pass. Tests never touch the network: use `tests/fakegh.py`.

## Adding a check

1. Write the function in `ghposture/checks.py` returning `list[Finding]`.
2. Register it in `REGISTRY` with an id, severity and one-line description.
3. Add a fixture in `tests/fixtures/` that fails it, and one that passes it.
4. Add the check to `docs/CHECKS.md` with the exact evidence it reports.

A check that cannot state its evidence in one line is not ready.

## Commit style

`check:`, `fix:`, `docs:`, `test:` prefix. One idea per commit.

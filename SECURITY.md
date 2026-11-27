# Security policy

## Reporting a vulnerability

Email **security@twinthos.com** with:

- the version (`ghposture --version`),
- the smallest workflow or repository state that reproduces the problem,
- what you expected and what happened.

Do not open a public issue for a security report. We acknowledge within three
working days and aim to ship a fix or a documented mitigation within thirty.

## Scope

In scope: the scanner itself, its parsers, and any case where it reports a pass
on something it did not actually check. **A false pass is a security bug in this
tool, not a cosmetic issue** — it is the failure mode that makes a scanner
dangerous, and it is treated as high severity.

Out of scope: the security of repositories you scan with it, and findings that
depend on a token with more privilege than documented.

## Supported versions

The latest release on the default branch. This is a single-maintainer project;
there are no long-term support branches.

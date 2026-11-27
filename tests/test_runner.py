from ghposture.runner import scan


class Stub:
    def __init__(self, meta, files=None):
        self.meta = meta
        self.files = files or {}
        self.calls = 0

    def get(self, path, params=None):
        self.calls += 1
        if path == "/repos/twinthos/demo":
            return dict(self.meta, security_and_analysis={
                "secret_scanning": {"status": "enabled"},
                "secret_scanning_push_protection": {"status": "enabled"}})
        if "/git/trees/" in path:
            return {"tree": [{"path": p} for p in self.files]}
        if "/contents/" in path:
            from ghposture.api import NotFound
            raise NotFound("x")
        from ghposture.api import NotFound
        raise NotFound(path)

    def status(self, path):
        return 404

    def paginate(self, path, params=None, limit=1000):
        return [self.meta]


def test_scan_records_every_check(meta):
    gh = Stub(meta, files=["README.md", "SECURITY.md", "CODEOWNERS", ".github/CODEOWNERS"])
    report = scan(gh, org="twinthos")
    checks_per_repo = [r for r in report.results if r.repo == "twinthos/demo"]
    assert len(checks_per_repo) >= 19
    assert report.repos_scanned == 1
    assert any(s for _, s in report.coverage.skipped)


def test_scan_uses_detailed_metadata_for_settings(meta):
    listed = {k: v for k, v in meta.items() if k != "security_and_analysis"}
    gh = Stub(listed, files=["README.md", "SECURITY.md", ".github/CODEOWNERS",
                             ".github/workflows/ci.yml"])
    report = scan(gh, org="twinthos")
    skipped = " ".join(reason for _, reason in report.coverage.skipped)
    assert "security settings" not in skipped
    assert not [f for f in report.findings if f.check in ("R001", "R002")]

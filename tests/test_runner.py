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


class ListingStub:
    """Org endpoint 404s; the owner listing returns public and private repos."""

    def __init__(self, repos):
        self.repos = repos
        self.calls = 0

    def get(self, path, params=None):
        self.calls += 1
        from ghposture.api import NotFound
        if path.startswith("/repos/"):
            name = path.split("/repos/", 1)[1]
            for repo in self.repos:
                if repo["full_name"] == name:
                    return dict(repo, security_and_analysis={
                        "secret_scanning": {"status": "enabled"},
                        "secret_scanning_push_protection": {"status": "enabled"}})
            raise NotFound(name)
        if "/git/trees/" in path:
            return {"tree": [{"path": "README.md"}]}
        if "/contents/" in path:
            raise NotFound(path)
        raise NotFound(path)

    def status(self, path):
        return 404

    def paginate(self, path, params=None, limit=1000):
        from ghposture.api import NotFound
        if path.startswith("/orgs/"):
            raise NotFound(path)
        if path == "/user/repos":
            return self.repos
        if path.startswith("/users/"):
            return [r for r in self.repos if not r["private"]]
        return []


def test_private_repos_are_included_for_owner():
    repos = [
        {"full_name": "twinthos/public-one", "name": "public-one", "private": False,
         "owner": {"login": "twinthos"}, "default_branch": "main", "archived": False},
        {"full_name": "twinthos/private-one", "name": "private-one", "private": True,
         "owner": {"login": "twinthos"}, "default_branch": "main", "archived": False},
        {"full_name": "someone/fork", "name": "fork", "private": False,
         "owner": {"login": "someone"}, "default_branch": "main", "archived": False},
    ]
    report = scan(ListingStub(repos), org="twinthos")
    assert report.repos_scanned == 2
    assert all(r.repo.startswith("twinthos/") for r in report.results)

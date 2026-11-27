import base64

from ghposture.api import NotFound


class FakeGitHub:
    """Stands in for the REST client. No network, fully deterministic."""

    def __init__(self, meta, files=None, statuses=None, responses=None):
        self.meta = meta
        self.files = files or {}
        self.statuses = statuses or {}
        self.responses = responses or {}
        self.calls = 0

    def get(self, path, params=None):
        self.calls += 1
        for key, value in self.responses.items():
            if path.startswith(key):
                return value
        if "/git/trees/" in path:
            return {"tree": [{"path": p} for p in sorted(self.files)]}
        if "/contents/" in path:
            rel = path.split("/contents/", 1)[1].split("?")[0]
            if rel in self.files:
                return {"content": base64.b64encode(self.files[rel].encode()).decode()}
            raise NotFound("no file")
        raise NotFound(path)

    def status(self, path):
        for key, value in self.statuses.items():
            if path.startswith(key):
                return value
        return 404

    def paginate(self, path, params=None, limit=1000):
        return [self.meta]

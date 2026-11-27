"""Minimal, defensive GitHub REST client. Standard library only.

Design rules:
  * every request has a timeout;
  * transient failures are retried with exponential backoff and jitter;
  * the token is never logged, echoed or included in exception text;
  * a permission error is data, not an exception: callers record it as
    "not checked" rather than as a pass.
"""
from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

API_ROOT = "https://api.github.com"


class ApiError(Exception):
    """Base error. Messages must never contain credentials."""


class NotFound(ApiError):
    pass


class Forbidden(ApiError):
    """Authenticated but not permitted. Callers degrade to 'not checked'."""


class RateLimited(ApiError):
    def __init__(self, reset_at: float | None):
        super().__init__("rate limited")
        self.reset_at = reset_at


class GitHub:
    def __init__(self, token: str, root: str = API_ROOT, timeout: float = 20.0,
                 retries: int = 3, sleep=time.sleep) -> None:
        if not token:
            raise ValueError("a token is required")
        self._token = token
        self._root = root.rstrip("/")
        self._timeout = timeout
        self._retries = retries
        self._sleep = sleep
        self.calls = 0

    def _request(self, method: str, path: str, params: dict | None = None,
                 body: dict | None = None) -> tuple[int, Any]:
        url = self._root + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        last: Exception | None = None
        for attempt in range(self._retries + 1):
            req = urllib.request.Request(url, data=data, method=method)
            req.add_header("Accept", "application/vnd.github+json")
            req.add_header("Authorization", f"Bearer {self._token}")
            req.add_header("User-Agent", "ghposture")
            if data:
                req.add_header("Content-Type", "application/json")
            try:
                self.calls += 1
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    raw = resp.read()
                    return resp.status, (json.loads(raw) if raw.strip() else None)
            except urllib.error.HTTPError as exc:
                code = exc.code
                if code in (401,):
                    raise Forbidden("authentication failed") from None
                if code == 403 or code == 429:
                    reset = exc.headers.get("X-RateLimit-Reset") if exc.headers else None
                    if reset and "rate limit" in (exc.reason or "").lower():
                        raise RateLimited(float(reset)) from None
                    if code == 403:
                        raise Forbidden("insufficient permission") from None
                if code == 404:
                    raise NotFound("not found") from None
                if code >= 500 and attempt < self._retries:
                    self._sleep(self._backoff(attempt))
                    continue
                raise ApiError(f"HTTP {code}") from None
            except (urllib.error.URLError, TimeoutError) as exc:
                last = exc
                if attempt < self._retries:
                    self._sleep(self._backoff(attempt))
                    continue
                raise ApiError(f"network error: {type(exc).__name__}") from None
        raise ApiError(f"exhausted retries: {type(last).__name__}")

    @staticmethod
    def _backoff(attempt: int) -> float:
        return min(8.0, (2 ** attempt) * 0.5) * (0.75 + random.random() / 2)

    def get(self, path: str, params: dict | None = None) -> Any:
        return self._request("GET", path, params)[1]

    def status(self, path: str) -> int:
        return self._request("GET", path)[0]

    def paginate(self, path: str, params: dict | None = None, limit: int = 1000) -> list:
        out: list = []
        page = 1
        params = dict(params or {})
        params.setdefault("per_page", 100)
        while len(out) < limit:
            params["page"] = page
            batch = self.get(path, params)
            if not isinstance(batch, list) or not batch:
                break
            out.extend(batch)
            if len(batch) < params["per_page"]:
                break
            page += 1
        return out[:limit]

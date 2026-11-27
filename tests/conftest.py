import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from fakegh import FakeGitHub  # noqa: E402,F401  re-exported for tests

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def meta():
    return {"name": "demo", "full_name": "twinthos/demo", "private": False,
            "archived": False, "default_branch": "main", "license": {"spdx_id": "Apache-2.0"},
            "security_and_analysis": {
                "secret_scanning": {"status": "enabled"},
                "secret_scanning_push_protection": {"status": "enabled"}}}


@pytest.fixture
def workflow_text():
    def load(name):
        return (FIXTURES / name).read_text()
    return load

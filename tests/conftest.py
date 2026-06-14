"""Shared pytest fixtures for the DualGuard suite (MG8).

Provides a temporary checkout directory and fake :class:`BugRecord` /
:class:`Patch` objects, and puts the repo root on ``sys.path`` so the tests run
with or without an editable install.
"""

from __future__ import annotations

import os
import sys

import pytest

# Ensure `import harness`, `import eval`, etc. resolve from the repo root even
# before `pip install -e .`.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from harness.verdict import BugRecord, Patch  # noqa: E402

_FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


@pytest.fixture
def fixtures_dir() -> str:
    """Absolute path to tests/fixtures/."""
    return _FIXTURES


@pytest.fixture
def tmp_checkout(tmp_path) -> str:
    """A temporary 'checkout' dir with a VUL4J/ metadata folder and a Java file."""
    checkout = tmp_path / "checkout"
    (checkout / "VUL4J").mkdir(parents=True)
    src = checkout / "src" / "main" / "java" / "demo"
    src.mkdir(parents=True)
    (src / "UserDao.java").write_text(
        "package demo;\npublic class UserDao {\n"
        "  public String q(String n) { return \"x\" + n; }\n}\n",
        encoding="utf-8",
    )
    return str(checkout)


@pytest.fixture
def fake_bug(tmp_checkout) -> BugRecord:
    """A minimal reproducible :class:`BugRecord` pointing at the tmp checkout."""
    return BugRecord(
        id="VUL4J-TEST",
        project="demo",
        cwe="CWE-89",
        source="vul4j",
        checkout_dir=tmp_checkout,
        pov_tests=["demo.UserDaoTest#testInjection"],
        vulnerable_file="src/main/java/demo/UserDao.java",
    )


@pytest.fixture
def fake_patch(fake_bug) -> Patch:
    """A minimal :class:`Patch` for ``fake_bug``."""
    return Patch(
        bug_id=fake_bug.id,
        patched_file_path=fake_bug.vulnerable_file,
        patched_code=(
            "package demo;\npublic class UserDao {\n"
            "  public String q(String n) { return prep(n); }\n"
            "  private String prep(String n) { return n; }\n}\n"
        ),
        model="test",
        attempt=0,
    )

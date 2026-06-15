"""WebGate (a11y gate) tests. axe-backed tests skip if Node/axe isn't installed."""

from __future__ import annotations

import os

import pytest

from harness import webgate

_DEMO = os.path.join(os.path.dirname(os.path.dirname(__file__)), "webgate", "demo")


def _axe_available() -> bool:
    try:
        webgate.run_axe(os.path.join(_DEMO, "fixed.html"))
        return True
    except Exception:  # noqa: BLE001 - node/axe not installed in this env
        return False


_needs_axe = pytest.mark.skipif(
    not _axe_available(),
    reason="Node/axe-core not installed (cd webgate && npm install)",
)


def _read(name: str) -> str:
    with open(os.path.join(_DEMO, name), encoding="utf-8") as fh:
        return fh.read()


def test_dom_non_deletion_guard_pure_python():
    # No axe needed — the DOM guard is pure Python.
    ok, ratio, _ = webgate.dom_non_deletion_ok(
        "<div><p>a</p><span>b</span><a>c</a></div>", "<div></div>"
    )
    assert ok is False and ratio < 0.6
    ok2, _, _ = webgate.dom_non_deletion_ok(
        "<div><p>a</p></div>", "<div><p>a</p></div>"
    )
    assert ok2 is True


def test_count_elements():
    assert webgate.count_elements("<a><b></b><c/></a>") == 3
    assert webgate.count_elements("") == 0


@_needs_axe
def test_broken_to_fixed_is_cleared():
    v = webgate.a11y_gate(_read("broken.html"), _read("fixed.html"), page_id="t")
    assert v.had_baseline_violations is True
    assert v.violations_after == 0
    assert v.a11y_flipped is True
    assert v.not_deleted is True
    assert v.cleared is True


@_needs_axe
def test_gamed_deletion_is_rejected():
    v = webgate.a11y_gate(_read("broken.html"), _read("gamed.html"), page_id="t")
    # axe is happy (elements deleted) but the DOM guard catches the cheat.
    assert v.a11y_flipped is True
    assert v.not_deleted is False
    assert v.cleared is False

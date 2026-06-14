"""MG1: GateVerdict.cleared truth table + to_dict() shape."""

from __future__ import annotations

import itertools

import pytest

from harness.verdict import GateVerdict, LayerResult


_FLAGS = (
    "compiles",
    "regression_pass",
    "pov_flipped",
    "semgrep_clean",
    "codeql_clean",
    "not_deleted",
)


def _make(**flags: bool) -> GateVerdict:
    base = {f: False for f in _FLAGS}
    base.update(flags)
    return GateVerdict(bug_id="B", **base)


def test_cleared_is_and_of_six():
    # Only the all-True combination clears.
    for combo in itertools.product([False, True], repeat=len(_FLAGS)):
        flags = dict(zip(_FLAGS, combo))
        v = _make(**flags)
        assert v.cleared is all(combo)


def test_each_false_blocks_clear():
    for missing in _FLAGS:
        flags = {f: True for f in _FLAGS}
        flags[missing] = False
        assert _make(**flags).cleared is False


def test_to_dict_injects_cleared():
    v = _make(**{f: True for f in _FLAGS})
    d = v.to_dict()
    assert d["cleared"] is True
    for f in _FLAGS:
        assert d[f] is True
    assert "layers" in d


def test_cleared_not_a_constructor_field():
    # `cleared` is a read-only @property; passing it must raise.
    with pytest.raises(TypeError):
        GateVerdict(  # type: ignore[call-arg]
            bug_id="B",
            compiles=True,
            regression_pass=True,
            pov_flipped=True,
            semgrep_clean=True,
            codeql_clean=True,
            not_deleted=True,
            cleared=True,
        )


def test_layers_default_empty_list():
    a = _make()
    b = _make()
    a.layers.append(LayerResult("compile", True, ""))
    assert b.layers == []  # default_factory, not a shared mutable default

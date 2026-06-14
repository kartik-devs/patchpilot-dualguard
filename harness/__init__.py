"""PatchPilot v2 "DualGuard" verification harness package.

Re-exports the canonical shared data contracts so downstream code can write
``from harness import BugRecord, Patch, LayerResult, GateVerdict``. These
contracts are defined ONCE in :mod:`harness.verdict`; never redefine them.
"""

from __future__ import annotations

from harness.verdict import (
    BugRecord,
    GateVerdict,
    LayerResult,
    Patch,
    SourceName,
)

__all__ = [
    "BugRecord",
    "Patch",
    "LayerResult",
    "GateVerdict",
    "SourceName",
]

__version__ = "2.0.0"

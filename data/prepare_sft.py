"""Top-level CLI shim for the SFT data-prep pipeline (delegates to data.prep).

The canonical, full implementation lives in ``data/prep/prepare_sft.py`` (MG6).
This module is a THIN, fully-runnable wrapper kept at the top of ``data/`` so the
pipeline can be invoked either way without code duplication:

    python -m data.prepare_sft  --raw data/raw/ ...        # via this shim
    python -m data.prep.prepare_sft --raw data/raw/ ...    # canonical module

Both paths share ONE implementation (single source of truth — see the repo
integration invariants). Everything public from ``data.prep.prepare_sft`` is
re-exported here (``main``, ``build_arg_parser``, ``load_raw``, ``dedup``,
``split_temporal``, ``split_by_cve``, ``to_sft_example``, ``write_jsonl``,
``INSTRUCTION``, ``RawRecord``) so existing imports and the ``pp-prep`` console
script keep working whichever name they target.

Contract (unchanged from the canonical module, SPEC §5):
  dedup (exact + token-Jaccard near-dup, keep earliest)
    -> temporal OR by-CVE split (no eval CVE/project leakage)
    -> strip leaky tokens from instruction+input
    -> emit instruction JSONL {instruction, input, output, meta}.

PUBLIC DATA ONLY. All emitted JSONL lands under data/ which is .gitignored.

Example:
    python -m data.prepare_sft --raw data/raw/ --out data/sft/train.jsonl \
        --eval-out data/sft/eval_heldout.jsonl --split temporal \
        [--cutoff-date 2022-01-01] [--cve-split] [--min-jaccard 0.9] [--seed 13]
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional

# Import the canonical implementation. Package-relative import is the normal
# case (``python -m data.prepare_sft``); the fallback lets this file be run
# directly as a script (``python data/prepare_sft.py``) by putting the repo root
# on sys.path so the ``data`` namespace package resolves.
try:
    from data.prep import prepare_sft as _impl
except Exception:  # pragma: no cover - direct-run fallback.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from data.prep import prepare_sft as _impl


# --- re-export the canonical public surface ----------------------------------
# Keeping these names available means callers may ``from data.prepare_sft import
# main`` exactly as they would from the canonical module.
INSTRUCTION = _impl.INSTRUCTION
RawRecord = _impl.RawRecord
load_raw = _impl.load_raw
dedup = _impl.dedup
split_temporal = _impl.split_temporal
split_by_cve = _impl.split_by_cve
assert_no_leakage = _impl.assert_no_leakage
to_sft_example = _impl.to_sft_example
write_jsonl = _impl.write_jsonl
build_arg_parser = _impl.build_arg_parser

__all__ = [
    "INSTRUCTION",
    "RawRecord",
    "load_raw",
    "dedup",
    "split_temporal",
    "split_by_cve",
    "assert_no_leakage",
    "to_sft_example",
    "write_jsonl",
    "build_arg_parser",
    "main",
]


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. Delegates verbatim to ``data.prep.prepare_sft.main``.

    Returns the underlying process exit code (0 ok, 1 error) so the ``pp-prep``
    console script and ``python -m data.prepare_sft`` behave identically to the
    canonical module.
    """
    return _impl.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())

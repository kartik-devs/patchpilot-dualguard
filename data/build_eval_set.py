"""Top-level CLI shim for eval-manifest assembly (delegates to data.prep).

The canonical, full implementation lives in ``data/prep/build_eval_set.py``
(MG6). This module is a THIN, fully-runnable wrapper kept at the top of
``data/`` so the manifest builder can be invoked either way without duplicating
logic:

    python -m data.build_eval_set      --vul4j-ids ... --out ...   # via this shim
    python -m data.prep.build_eval_set --vul4j-ids ... --out ...   # canonical

Both paths share ONE implementation (single source of truth — see the repo
integration invariants). The canonical public surface is re-exported here
(``main``, ``build_arg_parser``, ``load_cwe_focus``, ``build_vul4j_entries``,
``build_vjbench_entries``, ``entry_from_vul4j_meta``, ``entry_from_vjbench``,
``write_manifest``, ``Vul4JNotInstalled``) so existing imports and the
``pp-build-eval`` console script keep working whichever name they target.

Assembles the eval manifest the eval harness consumes: one ``EvalManifestEntry``
per line (id, project, cwe, source, vulnerable_file, pov_tests, human_patch_ref,
semgrep_covered, transformed). NO code checkout happens here — ``eval/run_eval``
does the actual ``vul4j checkout`` and inflates each entry into a
``harness.verdict.BugRecord``. ``semgrep_covered`` is True iff the bug's CWE
appears in ``config/cwe_focus.yaml`` (the AND-gate's "covered" stratum). Missing
``vul4j`` CLI never crashes the build — it warns once and emits stub entries.

PUBLIC DATA ONLY. The manifest (and data/) is .gitignored.

Example:
    python -m data.build_eval_set --vul4j-ids data/raw/vul4j_ids.txt \
        --vjbench data/raw/vjbench/ --out data/eval/manifest.jsonl \
        [--vul4j-meta data/raw/vul4j_meta.json] \
        [--cwe-focus config/cwe_focus.yaml] [--include-trans]
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional

# Import the canonical implementation; fall back to repo-root sys.path injection
# when this file is run directly (``python data/build_eval_set.py``).
try:
    from data.prep import build_eval_set as _impl
except Exception:  # pragma: no cover - direct-run fallback.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from data.prep import build_eval_set as _impl


# --- re-export the canonical public surface ----------------------------------
Vul4JNotInstalled = _impl.Vul4JNotInstalled
load_cwe_focus = _impl.load_cwe_focus
load_vul4j_meta_cache = _impl.load_vul4j_meta_cache
entry_from_vul4j_meta = _impl.entry_from_vul4j_meta
entry_from_vjbench = _impl.entry_from_vjbench
build_vul4j_entries = _impl.build_vul4j_entries
build_vjbench_entries = _impl.build_vjbench_entries
write_manifest = _impl.write_manifest
build_arg_parser = _impl.build_arg_parser

__all__ = [
    "Vul4JNotInstalled",
    "load_cwe_focus",
    "load_vul4j_meta_cache",
    "entry_from_vul4j_meta",
    "entry_from_vjbench",
    "build_vul4j_entries",
    "build_vjbench_entries",
    "write_manifest",
    "build_arg_parser",
    "main",
]


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. Delegates verbatim to ``data.prep.build_eval_set.main``.

    Returns the underlying process exit code (0 ok, 1 fatal input error) so the
    ``pp-build-eval`` console script and ``python -m data.build_eval_set``
    behave identically to the canonical module.
    """
    return _impl.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())

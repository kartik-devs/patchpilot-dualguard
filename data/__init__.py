"""PatchPilot v2 \"DualGuard\" data package.

Holds the MG6 data-prep code (``data.prep``) plus thin top-level CLI shims
(``data.prepare_sft`` / ``data.build_eval_set``) that delegate to it. Everything
this package PRODUCES lands under ``data/`` and is git-ignored (public-data-only
policy); only the code is committed. The canonical gate contracts live solely in
:mod:`harness.verdict` and are never redefined here.
"""

"""HTTP fixer client (MG5): generate a full-file Java patch from the vLLM fixer.

This is the spec's ``eval.fixer_client`` module. It speaks the OpenAI-compatible
``/v1/chat/completions`` protocol via the shared :mod:`serve.dualguard` client and
the canonical :mod:`serving.prompts` builders. The public entry point matches the
spec signature exactly so :mod:`eval.run_eval` can call it by keyword::

    generate_patch(bug=..., attempt=..., base_url=..., model=...,
                   feedback=..., temperature=...)  -> Patch

Note there is NO ``original_code`` parameter: the client reads the current
(vulnerable) contents of ``bug.vulnerable_file`` from ``bug.checkout_dir`` itself,
so callers need not pass it. Contracts come from :mod:`harness.verdict`.
"""

from __future__ import annotations

import os
from typing import Optional

from harness.verdict import BugRecord, Patch
from serve.dualguard import DualGuardClient, DualGuardConfig


def read_original_code(bug: BugRecord) -> str:
    """Read the current vulnerable file from the checkout ("" if unreadable)."""
    if not bug.checkout_dir or not bug.vulnerable_file:
        return ""
    path = os.path.join(bug.checkout_dir, bug.vulnerable_file)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def generate_patch(
    bug: BugRecord,
    attempt: int,
    base_url: str,
    model: str,
    feedback: Optional[str] = None,
    temperature: float = 0.2,
    original_code: Optional[str] = None,
) -> Patch:
    """Generate one candidate patch for ``bug`` via the vLLM fixer.

    POSTs to ``base_url`` (OpenAI-compatible). Uses ``serving.prompts.build_fix_prompt``
    (through the shared client) and extracts the fenced ```java full-file block.

    Args:
        bug: The vulnerability to repair.
        attempt: 0-based retry index (recorded on the returned Patch).
        base_url: vLLM ``/v1`` base URL, e.g. ``http://localhost:8000/v1``.
        model: Served model name (e.g. ``fixer``).
        feedback: Optional gate-failure feedback to append on a retry.
        temperature: Sampling temperature.
        original_code: Optional pre-read vulnerable source; if omitted it is read
            from the checkout. (Kept optional so both the spec call convention and
            callers that already have the source work.)

    Returns:
        A :class:`harness.verdict.Patch` whose ``patched_code`` is the FULL file.
    """
    if original_code is None:
        original_code = read_original_code(bug)
    client = DualGuardClient(
        DualGuardConfig(base_url=base_url, model=model, temperature=temperature)
    )
    return client.fix(bug, original_code, feedback=feedback, attempt=attempt)


__all__ = ["generate_patch", "read_original_code"]

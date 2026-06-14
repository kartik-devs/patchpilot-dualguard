"""HTTP judge client (MG5): LLM-as-judge ranking of candidate patches.

This is the spec's ``eval.judge_client`` module. The judge VOTE only RANKS
candidates before the executable gate runs; the gate (``GateVerdict.cleared``)
remains the ground-truth success oracle. Signatures match the spec so
:mod:`eval.run_eval` can call ``rank(bug, candidates, base_url, model)``.

Delegates transport/parsing to the shared :mod:`serve.dualguard` client; contracts
come from :mod:`harness.verdict`.
"""

from __future__ import annotations

from typing import List

from harness.verdict import BugRecord, Patch
from serve.dualguard import DualGuardClient, DualGuardConfig, JudgeVote


def judge_patch(
    bug: BugRecord, patch: Patch, base_url: str, model: str
) -> JudgeVote:
    """Score one candidate patch with the judge model.

    Args:
        bug: The vulnerability the patch targets.
        patch: The candidate patch.
        base_url: vLLM ``/v1`` base URL for the judge (e.g. ``:8001/v1``).
        model: Served judge model name.

    Returns:
        A :class:`serve.dualguard.JudgeVote` (accept, reason, score).
    """
    client = DualGuardClient(
        DualGuardConfig(base_url=base_url, model=model, temperature=0.0)
    )
    return client.judge(bug, patch)


def rank(
    bug: BugRecord, candidates: List[Patch], base_url: str, model: str
) -> Patch:
    """Return the highest-scored candidate (tie-break: lowest attempt index).

    Args:
        bug: The vulnerability.
        candidates: One or more candidate patches (best-of-n).
        base_url: vLLM ``/v1`` base URL for the judge.
        model: Served judge model name.

    Returns:
        The chosen :class:`harness.verdict.Patch`.
    """
    client = DualGuardClient(
        DualGuardConfig(base_url=base_url, model=model, temperature=0.0)
    )
    return client.rank(bug, candidates)


__all__ = ["judge_patch", "rank", "JudgeVote"]

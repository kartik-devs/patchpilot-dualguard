"""Canonical prompt builders for the DualGuard fixer & judge (MG7).

Single source of truth for the system prompts and the user-message builders used
by :mod:`serve.dualguard` (the OpenAI-compatible vLLM client) and the eval
clients. The fixer is instructed to return the FULL patched file in ONE fenced
``java`` block (never a diff — integration invariant #4). The judge returns a
strict JSON object ``{"accept": bool, "score": 0..1, "reason": "..."}``.

Contracts (BugRecord, Patch) come from :mod:`harness.verdict`; never redefined.
"""

from __future__ import annotations

from typing import List, Optional

from harness.verdict import BugRecord, Patch


FIXER_SYSTEM = (
    "You are a senior Java security engineer. You repair a single vulnerable Java "
    "source file. You MUST preserve all existing behavior and public APIs, change as "
    "little as possible, and fix ONLY the security vulnerability. Do NOT delete the "
    "vulnerable method or its surrounding logic to make a scanner go quiet. Return the "
    "COMPLETE patched file (the entire file, not a diff) inside a single fenced "
    "```java code block, and output nothing else."
)

JUDGE_SYSTEM = (
    "You are a strict Java application-security reviewer acting as an LLM judge. You "
    "decide whether a candidate patch closes the described vulnerability WITHOUT "
    "breaking behavior or deleting functionality. Respond with ONLY a single JSON "
    'object: {"accept": <true|false>, "score": <float 0..1>, "reason": "<short '
    'justification>"}. Do not output anything except that JSON object.'
)


def build_fix_prompt(
    bug: BugRecord, original_code: str, feedback: Optional[str] = None
) -> str:
    """Build the fixer USER message for one bug.

    Deliberately omits CWE/CVE/path identifiers so the model repairs from code
    structure rather than memorized labels (consistent with the leak-stripped
    training data). When ``feedback`` is given (a retry), the gate's failure
    summary is appended.

    Args:
        bug: The vulnerability under repair (only non-leaky fields are surfaced).
        original_code: Full current contents of the vulnerable file.
        feedback: Optional verification-gate feedback from a previous attempt.

    Returns:
        The user-message string.
    """
    parts: List[str] = [
        "Fix the security vulnerability in the following Java file. Infer the issue "
        "from the code itself; do not rely on any vulnerability identifiers.",
        f"Project: {bug.project or 'unknown'}",
        f"File: {bug.vulnerable_file or 'unknown'}",
    ]
    if feedback:
        parts.append(
            "A previous attempt FAILED the verification gate. Address this feedback "
            "and try again:\n" + feedback.strip()
        )
    parts.append(
        "Return the COMPLETE corrected file inside one fenced ```java block:\n\n"
        "```java\n" + (original_code or "") + "\n```"
    )
    return "\n\n".join(parts)


def build_judge_prompt(bug: BugRecord, patch: Patch) -> str:
    """Build the judge USER message scoring one candidate patch.

    Args:
        bug: The vulnerability the patch targets.
        patch: The candidate full-file patch.

    Returns:
        The user-message string requesting a strict-JSON verdict.
    """
    return (
        "Evaluate whether the candidate patch below closes the vulnerability while "
        "preserving behavior and NOT deleting functionality.\n\n"
        f"Project: {bug.project or 'unknown'}\n"
        f"File: {patch.patched_file_path or bug.vulnerable_file}\n\n"
        "Candidate patched file:\n\n"
        "```java\n" + (patch.patched_code or "") + "\n```\n\n"
        'Respond with ONLY the JSON object: {"accept": bool, "score": 0..1, '
        '"reason": "..."}.'
    )


__all__ = [
    "FIXER_SYSTEM",
    "JUDGE_SYSTEM",
    "build_fix_prompt",
    "build_judge_prompt",
]

"""DualGuard client: OpenAI-compatible access to the co-resident vLLM fixer and judge.

One thin client speaks the OpenAI ``/v1/chat/completions`` protocol that vLLM exposes, so
the same code path drives either the fixer (port 8000, returns a full patched Java file) or
the judge (port 8001, returns a strict-JSON accept/score/reason vote). The two servers are
co-resident on a single MI300X (see ``serve/launch_vllm.sh``); this module is the Python
entry point the eval harness and UI use to talk to them.

Public surface (stable contract for sibling modules):
    DualGuardConfig                         -- endpoint/model/sampling config
    DualGuardClient(cfg)                    -- the client
        .fix(bug, original_code, feedback, attempt) -> Patch
        .judge(bug, patch)                  -> JudgeVote
        .rank(bug, candidates)              -> Patch          (highest judge score)
    JudgeVote(accept, score, reason)        -- judge result dataclass

Contracts come from :mod:`harness.verdict` (BugRecord, Patch) -- never redefined here.
Prompt builders come from :mod:`serving.prompts` when available; a self-contained fallback
is used otherwise so this file runs standalone.

If the ``requests`` library or the vLLM endpoint is unavailable the client raises a typed
:class:`DualGuardError` with a clear remediation string -- never a cryptic crash.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from harness.verdict import BugRecord, Patch

try:  # requests is in requirements.txt; degrade gracefully if absent.
    import requests  # type: ignore
except ImportError:  # pragma: no cover - exercised only when dep missing
    requests = None  # type: ignore


# --------------------------------------------------------------------------- #
# Prompt builders: prefer the shared serving.prompts module (MG7). Fall back to
# inline equivalents so this client is runnable before that module lands and so
# the demo never hard-depends on import order across the parallel build.
# --------------------------------------------------------------------------- #
try:  # pragma: no cover - import availability depends on build order
    from serving.prompts import (  # type: ignore
        FIXER_SYSTEM,
        JUDGE_SYSTEM,
        build_fix_prompt,
        build_judge_prompt,
    )

    _USING_SHARED_PROMPTS = True
except Exception:  # noqa: BLE001 - any import failure -> use fallback
    _USING_SHARED_PROMPTS = False

    FIXER_SYSTEM = (
        "You are a senior Java security engineer. You repair a single vulnerable Java "
        "source file. You MUST preserve all existing behavior and public APIs, change as "
        "little as possible, and fix ONLY the security vulnerability. Return the COMPLETE "
        "patched file (the entire file, not a diff) inside a single fenced ```java code "
        "block, and nothing else."
    )

    JUDGE_SYSTEM = (
        "You are a strict Java application-security reviewer acting as an LLM judge. You "
        "decide whether a candidate patch closes the described vulnerability WITHOUT "
        "breaking behavior or deleting functionality. Respond with ONLY a single JSON "
        'object: {"accept": <true|false>, "score": <float 0..1>, "reason": "<short '
        'justification>"}. Do not output anything except that JSON object.'
    )

    def build_fix_prompt(  # type: ignore[misc]
        bug: BugRecord, original_code: str, feedback: Optional[str] = None
    ) -> str:
        """Fallback user prompt for the fixer (used when serving.prompts is unavailable)."""
        parts: List[str] = []
        parts.append(
            "Fix the security vulnerability in the following Java file. Do not reveal or "
            "rely on any vulnerability identifiers; infer the issue from the code."
        )
        parts.append(f"Project: {bug.project or 'unknown'}")
        parts.append(f"File: {bug.vulnerable_file or 'unknown'}")
        if feedback:
            parts.append(
                "A previous attempt failed the verification gate. Address this feedback "
                "and try again:\n" + feedback.strip()
            )
        parts.append(
            "Return the COMPLETE corrected file inside one fenced ```java block:\n\n"
            "```java\n" + original_code + "\n```"
        )
        return "\n\n".join(parts)

    def build_judge_prompt(bug: BugRecord, patch: Patch) -> str:  # type: ignore[misc]
        """Fallback user prompt for the judge."""
        return (
            "Evaluate whether the candidate patch below closes the vulnerability while "
            "preserving behavior and not deleting functionality.\n\n"
            f"Project: {bug.project or 'unknown'}\n"
            f"File: {patch.patched_file_path or bug.vulnerable_file}\n\n"
            "Candidate patched file:\n\n"
            "```java\n" + patch.patched_code + "\n```\n\n"
            'Respond with ONLY the JSON object: {"accept": bool, "score": 0..1, '
            '"reason": "..."}.'
        )


class DualGuardError(RuntimeError):
    """Raised when the vLLM endpoint cannot be reached or returns an unusable response."""


@dataclass
class DualGuardConfig:
    """Connection + sampling settings for one OpenAI-compatible vLLM endpoint.

    Attributes:
        base_url: Endpoint root, e.g. ``http://localhost:8000/v1``.
        model: Served model name, e.g. ``fixer`` or ``judge`` (vLLM --served-model-name).
        temperature: Sampling temperature.
        max_tokens: Max completion tokens.
        top_p: Nucleus sampling parameter.
        timeout: Per-request HTTP timeout in seconds.
        api_key: Bearer token (vLLM accepts any non-empty value by default).
    """

    base_url: str
    model: str
    temperature: float = 0.2
    max_tokens: int = 4096
    top_p: float = 0.95
    timeout: int = 600
    api_key: str = "EMPTY"

    @property
    def chat_url(self) -> str:
        """Full ``/chat/completions`` URL for this endpoint."""
        return self.base_url.rstrip("/") + "/chat/completions"


@dataclass
class JudgeVote:
    """One judge decision over a candidate patch.

    Attributes:
        accept: Whether the judge believes the patch is acceptable.
        score: Confidence in ``[0.0, 1.0]`` used to rank candidates pre-gate.
        reason: Short natural-language justification.
    """

    accept: bool
    reason: str
    score: float

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serializable view."""
        return asdict(self)


# Matches the FIRST fenced code block, preferring ```java but accepting a bare ``` fence.
_FENCE_RE = re.compile(
    r"```[ \t]*(?:java|jsp)?[ \t]*\r?\n(?P<body>.*?)```",
    re.DOTALL | re.IGNORECASE,
)
# Matches the first balanced-ish JSON object for judge parsing.
_JSON_OBJ_RE = re.compile(r"\{.*\}", re.DOTALL)


def extract_java_block(text: str) -> str:
    """Pull the model's full patched file out of its chat response.

    Prefers the first fenced ```java block. If no fence is present (some models omit it
    when the system prompt is strict), the raw text is returned stripped, on the
    assumption it is the file body. Always returns a non-None string.

    Args:
        text: Raw assistant message content.

    Returns:
        The extracted Java source.
    """
    if not text:
        return ""
    match = _FENCE_RE.search(text)
    if match:
        return match.group("body").strip("\n")
    return text.strip()


def parse_judge_json(text: str) -> JudgeVote:
    """Parse a judge response into a :class:`JudgeVote`, tolerating minor noise.

    Strategy: find the first ``{...}`` object, ``json.loads`` it, coerce fields. If parsing
    fails entirely, return a conservative reject vote (``accept=False, score=0.0``) carrying
    the raw text as the reason -- the executable gate remains ground truth, so a malformed
    judge vote must never accept by default.
    """
    raw = (text or "").strip()
    candidate = raw
    if not (raw.startswith("{") and raw.endswith("}")):
        m = _JSON_OBJ_RE.search(raw)
        if m:
            candidate = m.group(0)
    try:
        obj = json.loads(candidate)
    except (json.JSONDecodeError, TypeError):
        return JudgeVote(
            accept=False,
            reason=f"unparseable judge response: {raw[:200]}",
            score=0.0,
        )
    accept = bool(obj.get("accept", False))
    try:
        score = float(obj.get("score", 1.0 if accept else 0.0))
    except (TypeError, ValueError):
        score = 1.0 if accept else 0.0
    score = max(0.0, min(1.0, score))
    reason = str(obj.get("reason", ""))
    return JudgeVote(accept=accept, reason=reason, score=score)


class DualGuardClient:
    """OpenAI-compatible client for the DualGuard fixer/judge vLLM servers."""

    def __init__(self, cfg: DualGuardConfig) -> None:
        """Store config. Validates that ``requests`` is importable.

        Raises:
            DualGuardError: if the ``requests`` dependency is missing.
        """
        if requests is None:
            raise DualGuardError(
                "the 'requests' package is required for DualGuardClient -- "
                "install it with: pip install -r requirements-harness.txt"
            )
        self.cfg = cfg

    # ----------------------------- transport ------------------------------- #
    def _chat(self, system: str, user: str) -> str:
        """POST one chat-completion request and return the assistant message content.

        Raises:
            DualGuardError: on connection failure, non-2xx status, or malformed body,
                each with a clear remediation hint.
        """
        payload: Dict[str, Any] = {
            "model": self.cfg.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.cfg.temperature,
            "max_tokens": self.cfg.max_tokens,
            "top_p": self.cfg.top_p,
        }
        headers = {
            "Authorization": f"Bearer {self.cfg.api_key}",
            "Content-Type": "application/json",
        }
        try:
            resp = requests.post(  # type: ignore[union-attr]
                self.cfg.chat_url,
                json=payload,
                headers=headers,
                timeout=self.cfg.timeout,
            )
        except Exception as exc:  # noqa: BLE001 - surface any transport error uniformly
            raise DualGuardError(
                f"could not reach vLLM at {self.cfg.chat_url}: {exc}. "
                "Is the server up? See serve/launch_vllm.sh."
            ) from exc

        if resp.status_code >= 400:
            raise DualGuardError(
                f"vLLM returned HTTP {resp.status_code} from {self.cfg.chat_url}: "
                f"{resp.text[:500]}"
            )
        try:
            body = resp.json()
            return body["choices"][0]["message"]["content"] or ""
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise DualGuardError(
                f"malformed completion from {self.cfg.chat_url}: {exc}; "
                f"raw={resp.text[:300]}"
            ) from exc

    # ------------------------------- fixer --------------------------------- #
    def fix(
        self,
        bug: BugRecord,
        original_code: str,
        feedback: Optional[str] = None,
        attempt: int = 0,
    ) -> Patch:
        """Generate a candidate patch for one bug: ``fix(bug) -> Patch``.

        Sends the fixer system prompt + a build_fix_prompt user message, extracts the
        fenced Java block, and wraps it as a full-file :class:`harness.verdict.Patch`
        (``patched_code`` is the ENTIRE file, never a diff -- integration invariant #4).

        Args:
            bug: The vulnerability to repair.
            original_code: Full current contents of ``bug.vulnerable_file``.
            feedback: Optional gate-failure feedback to append for a retry.
            attempt: 0-based retry index (recorded on the Patch).

        Returns:
            A :class:`harness.verdict.Patch`.
        """
        user = build_fix_prompt(bug, original_code, feedback)
        content = self._chat(FIXER_SYSTEM, user)
        patched_code = extract_java_block(content)
        if not patched_code.strip():
            # Keep the original so downstream gate layers fail cleanly rather than
            # the client crashing; this naturally yields not-cleared.
            patched_code = original_code
        return Patch(
            bug_id=bug.id,
            patched_file_path=bug.vulnerable_file,
            patched_code=patched_code,
            model=self.cfg.model,
            attempt=attempt,
        )

    # ------------------------------- judge --------------------------------- #
    def judge(self, bug: BugRecord, patch: Patch) -> JudgeVote:
        """Score one candidate patch: ``judge(patch) -> verdict`` (a :class:`JudgeVote`).

        The LLM-as-judge vote is advisory: it RANKS candidates before the executable
        gate runs. The gate (compile/regression/PoV/SAST/AST) remains the ground-truth
        success oracle (``GateVerdict.cleared``).

        Args:
            bug: The vulnerability the patch targets.
            patch: The candidate patch.

        Returns:
            A :class:`JudgeVote`.
        """
        user = build_judge_prompt(bug, patch)
        content = self._chat(JUDGE_SYSTEM, user)
        return parse_judge_json(content)

    def rank(self, bug: BugRecord, candidates: List[Patch]) -> Patch:
        """Return the highest-scored candidate by judge score.

        Tie-break: lowest ``attempt`` index (prefer the earlier/cheaper candidate).
        Empty input raises ``DualGuardError``. If every judge call fails, the first
        candidate is returned so the pipeline still makes progress.

        Args:
            bug: The vulnerability.
            candidates: One or more candidate patches (e.g. best-of-n).

        Returns:
            The chosen :class:`harness.verdict.Patch`.
        """
        if not candidates:
            raise DualGuardError("rank() requires at least one candidate patch")
        best: Optional[Patch] = None
        best_score = -1.0
        for cand in candidates:
            try:
                vote = self.judge(bug, cand)
                score = vote.score
            except DualGuardError:
                score = -1.0
            if score > best_score or (
                score == best_score
                and best is not None
                and cand.attempt < best.attempt
            ):
                best = cand
                best_score = score
        return best if best is not None else candidates[0]


def _read_original_from_checkout(bug: BugRecord) -> str:
    """Best-effort read of ``bug.vulnerable_file`` from ``bug.checkout_dir`` ("" if absent)."""
    if not bug.checkout_dir or not bug.vulnerable_file:
        return ""
    path = os.path.join(bug.checkout_dir, bug.vulnerable_file)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


# Backwards/forwards-friendly functional wrappers matching the spec's client signatures
# (eval.fixer_client.generate_patch / eval.judge_client.judge_patch / rank) so callers can
# use either the class or these free functions interchangeably.
def generate_patch(
    bug: BugRecord,
    attempt: int,
    base_url: str,
    model: str,
    feedback: Optional[str] = None,
    temperature: float = 0.2,
    original_code: Optional[str] = None,
) -> Patch:
    """Functional form of :meth:`DualGuardClient.fix` (OpenAI-compatible fixer call).

    Matches the spec's ``eval.fixer_client.generate_patch`` signature: ``original_code``
    is OPTIONAL and, when omitted, is read from ``bug.checkout_dir/bug.vulnerable_file``.
    This lets :mod:`eval.run_eval` call ``generate_patch(bug=..., attempt=..., base_url=...,
    model=..., feedback=..., temperature=...)`` without passing the source explicitly.
    """
    if original_code is None:
        original_code = _read_original_from_checkout(bug)
    cfg = DualGuardConfig(base_url=base_url, model=model, temperature=temperature)
    return DualGuardClient(cfg).fix(bug, original_code, feedback=feedback, attempt=attempt)


def judge_patch(
    bug: BugRecord, patch: Patch, base_url: str, model: str
) -> JudgeVote:
    """Functional form of :meth:`DualGuardClient.judge`."""
    cfg = DualGuardConfig(base_url=base_url, model=model, temperature=0.0)
    return DualGuardClient(cfg).judge(bug, patch)


def rank(
    bug: BugRecord, candidates: List[Patch], base_url: str, model: str
) -> Patch:
    """Functional form of :meth:`DualGuardClient.rank`."""
    cfg = DualGuardConfig(base_url=base_url, model=model, temperature=0.0)
    return DualGuardClient(cfg).rank(bug, candidates)


# --------------------------------------------------------------------------- #
# CLI: smoke-test the fixer or judge against a running vLLM server.
# --------------------------------------------------------------------------- #
def _load_bug(path: Optional[str], fallback_id: str = "DEMO-1") -> BugRecord:
    """Load a BugRecord from JSON, or synthesise a minimal demo bug."""
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            d = json.load(fh)
        return BugRecord(
            id=d["id"],
            project=d.get("project", ""),
            cwe=d.get("cwe", ""),
            source=d.get("source", "vul4j"),
            checkout_dir=d.get("checkout_dir", ""),
            pov_tests=list(d.get("pov_tests", [])),
            vulnerable_file=d["vulnerable_file"],
        )
    return BugRecord(
        id=fallback_id,
        project="demo",
        cwe="CWE-89",
        source="vul4j",
        checkout_dir="",
        pov_tests=[],
        vulnerable_file="Demo.java",
    )


def _read_text(path: Optional[str], default: str) -> str:
    """Read a text file or return a default snippet."""
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    return default


def main(argv: Optional[List[str]] = None) -> int:
    """CLI: drive the DualGuard fixer or judge against a live vLLM endpoint.

    Examples:
        python -m serve.dualguard fix  --base-url http://localhost:8000/v1 \\
            --model fixer --code MyFile.java --bug bug.json -o patch.json
        python -m serve.dualguard judge --base-url http://localhost:8001/v1 \\
            --model judge --bug bug.json --patch patch.json
    """
    parser = argparse.ArgumentParser(
        prog="serve.dualguard",
        description="DualGuard OpenAI-compatible client: fix(bug)->patch, judge(patch)->verdict.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    pf = sub.add_parser("fix", help="Generate a patch from the fixer server.")
    pf.add_argument("--base-url", required=True, help="vLLM /v1 base URL, e.g. http://localhost:8000/v1")
    pf.add_argument("--model", required=True, help="Served model name (e.g. fixer).")
    pf.add_argument("--bug", default=None, help="Path to a BugRecord JSON (optional; demo bug otherwise).")
    pf.add_argument("--code", default=None, help="Path to the vulnerable Java file (optional).")
    pf.add_argument("--feedback", default=None, help="Optional gate-failure feedback text.")
    pf.add_argument("--attempt", type=int, default=0, help="Retry index recorded on the patch.")
    pf.add_argument("--temperature", type=float, default=0.2)
    pf.add_argument("-o", "--out", default=None, help="Write the Patch JSON here.")

    pj = sub.add_parser("judge", help="Score a patch with the judge server.")
    pj.add_argument("--base-url", required=True, help="vLLM /v1 base URL, e.g. http://localhost:8001/v1")
    pj.add_argument("--model", required=True, help="Served model name (e.g. judge).")
    pj.add_argument("--bug", default=None, help="Path to a BugRecord JSON (optional).")
    pj.add_argument("--patch", required=True, help="Path to a Patch JSON (from `fix`).")

    args = parser.parse_args(argv)

    try:
        if args.cmd == "fix":
            bug = _load_bug(args.bug)
            original = _read_text(
                args.code,
                "public class Demo {\n  // vulnerable demo placeholder\n}\n",
            )
            cfg = DualGuardConfig(
                base_url=args.base_url, model=args.model, temperature=args.temperature
            )
            patch = DualGuardClient(cfg).fix(
                bug, original, feedback=args.feedback, attempt=args.attempt
            )
            out = json.dumps(asdict(patch), indent=2)
            if args.out:
                with open(args.out, "w", encoding="utf-8") as fh:
                    fh.write(out)
                print(f"wrote patch -> {args.out}")
            else:
                print(out)
            return 0

        if args.cmd == "judge":
            bug = _load_bug(args.bug)
            with open(args.patch, "r", encoding="utf-8") as fh:
                pd = json.load(fh)
            patch = Patch(
                bug_id=pd.get("bug_id", bug.id),
                patched_file_path=pd.get("patched_file_path", bug.vulnerable_file),
                patched_code=pd.get("patched_code", ""),
                model=pd.get("model", ""),
                attempt=int(pd.get("attempt", 0)),
            )
            cfg = DualGuardConfig(base_url=args.base_url, model=args.model, temperature=0.0)
            vote = DualGuardClient(cfg).judge(bug, patch)
            print(json.dumps(vote.to_dict(), indent=2))
            return 0
    except DualGuardError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"error: file not found: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

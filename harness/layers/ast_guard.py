"""MG4 · AST non-deletion guard: defeat the "delete-the-sink" gaming failure.

A patch can make Semgrep/CodeQL go quiet simply by deleting the vulnerable code
path (gutting a method, returning ``null``, dropping a branch). Such a patch is
"clean" yet worthless. This layer rejects patches that drop reachable statements
or return/throw paths below a retained-ratio threshold.

Primary path uses ``javalang`` (pure Python, no JVM) to count statement-like AST
nodes and return/throw paths in the original vs patched file. If ``javalang`` is
unavailable it degrades to a line-based heuristic; if the *patched* code fails to
parse while ``javalang`` IS available, the patch is hard-rejected (unparseable
"fix" is never acceptable on the AST path).

Public API (consumed by ``harness.gate``):
    non_deletion_ok(original, patched, min_retained_ratio=0.6) -> NonDeletionResult
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional, Tuple


@dataclass
class NonDeletionResult:
    """Outcome of the non-deletion guard.

    Attributes:
        ok: True iff the patch retained enough statements AND return/throw paths.
        retained_ratio: patched_stmts / original_stmts (1.0 if original is empty).
        returns_kept: True iff patched return+throw count >= original count.
        original_stmts / patched_stmts: statement-like node counts.
        original_returns / patched_returns: return+throw path counts.
        detail: human-readable explanation.
        method: "ast" (javalang) or "line" (fallback).
    """

    ok: bool
    retained_ratio: float
    returns_kept: bool
    original_stmts: int
    patched_stmts: int
    original_returns: int
    patched_returns: int
    detail: str
    method: str = "ast"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _try_import_javalang():
    """Return the ``javalang`` module, or ``None`` if it is not installed."""
    try:
        import javalang  # type: ignore

        return javalang
    except Exception:  # noqa: BLE001 - any import failure -> fallback path
        return None


def _statement_types(javalang) -> tuple:
    """Tuple of javalang statement-like node classes that actually exist."""
    names = [
        "StatementExpression",
        "LocalVariableDeclaration",
        "ReturnStatement",
        "ThrowStatement",
        "IfStatement",
        "ForStatement",
        "WhileStatement",
        "DoStatement",
        "SwitchStatement",
        "TryStatement",
        "SynchronizedStatement",
        "AssertStatement",
        "BreakStatement",
        "ContinueStatement",
    ]
    out = []
    for n in names:
        t = getattr(javalang.tree, n, None)
        if t is not None:
            out.append(t)
    return tuple(out)


def _return_types(javalang) -> tuple:
    out = []
    for n in ("ReturnStatement", "ThrowStatement"):
        t = getattr(javalang.tree, n, None)
        if t is not None:
            out.append(t)
    return tuple(out)


def _count_ast(javalang, code: str) -> Optional[Tuple[int, int]]:
    """Return (statement_count, return+throw_count) or None if parsing fails."""
    try:
        tree = javalang.parse.parse(code)
    except Exception:  # noqa: BLE001 - syntactically invalid Java
        return None
    stmt_types = _statement_types(javalang)
    ret_types = _return_types(javalang)
    stmts = 0
    for t in stmt_types:
        stmts += sum(1 for _ in tree.filter(t))
    rets = 0
    for t in ret_types:
        rets += sum(1 for _ in tree.filter(t))
    return stmts, rets


def _count_lines(code: str) -> Tuple[int, int]:
    """Line-based fallback statement / return-path counter."""
    stmts = 0
    rets = 0
    for raw in (code or "").splitlines():
        s = raw.strip()
        if not s or s in ("{", "}") or s.startswith(("//", "*", "/*", "*/", "@")):
            continue
        stmts += 1
        if "return" in s or "throw" in s:
            rets += 1
    return stmts, rets


def non_deletion_ok(
    original: str, patched: str, min_retained_ratio: float = 0.6
) -> NonDeletionResult:
    """Check whether ``patched`` preserved enough of ``original``'s body.

    Args:
        original: The original (vulnerable) file contents.
        patched: The candidate patched file contents (full file).
        min_retained_ratio: Minimum patched/original statement ratio to accept.

    Returns:
        A :class:`NonDeletionResult`. ``ok`` is True iff the statement ratio meets
        the threshold AND return/throw paths were not dropped.
    """
    javalang = _try_import_javalang()
    method = "line"

    if javalang is not None:
        pc = _count_ast(javalang, patched)
        oc = _count_ast(javalang, original)
        if pc is None:
            # Unparseable "fix" is never acceptable on the AST path.
            o_stmts, o_rets = oc if oc is not None else _count_lines(original)
            return NonDeletionResult(
                ok=False,
                retained_ratio=0.0,
                returns_kept=False,
                original_stmts=o_stmts,
                patched_stmts=0,
                original_returns=o_rets,
                patched_returns=0,
                detail="patched code failed to parse (javalang) -> rejected",
                method="ast",
            )
        if oc is not None:
            method = "ast"
            o_stmts, o_rets = oc
            p_stmts, p_rets = pc
        else:
            method = "line"  # original unparseable: degrade both for consistency

    if method == "line":
        o_stmts, o_rets = _count_lines(original)
        p_stmts, p_rets = _count_lines(patched)

    retained_ratio = (p_stmts / o_stmts) if o_stmts > 0 else 1.0
    returns_kept = p_rets >= o_rets
    ok = (retained_ratio >= min_retained_ratio) and returns_kept
    detail = (
        f"method={method}; stmts patched/original={p_stmts}/{o_stmts} "
        f"ratio={retained_ratio:.3f} (min={min_retained_ratio}); "
        f"returns+throws patched/original={p_rets}/{o_rets}; "
        f"returns_kept={returns_kept}"
    )
    return NonDeletionResult(
        ok=ok,
        retained_ratio=retained_ratio,
        returns_kept=returns_kept,
        original_stmts=o_stmts,
        patched_stmts=p_stmts,
        original_returns=o_rets,
        patched_returns=p_rets,
        detail=detail,
        method=method,
    )


__all__ = ["NonDeletionResult", "non_deletion_ok"]

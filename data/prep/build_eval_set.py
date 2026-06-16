"""Assemble the Vul4J + VJBench eval manifest consumed by eval/run_eval.py.

Emits ``data/eval/manifest.jsonl`` -- one ``EvalManifestEntry`` per line. NO code
checkout happens here; the eval harness does the actual ``vul4j checkout`` later.

Sources (SPEC §5, MG6):
  * Vul4J : the 79 PoV-reproducible vulns. For each id in ``--vul4j-ids`` we pull
    metadata (cwe, project, vulnerable_file, pov_tests, human_patch_ref) from the
    ``vul4j info <id>`` CLI when available, falling back to a cached/local JSON
    metadata file, and finally to a minimal stub entry (never crash).
  * VJBench / llm-vul : 35 Vul4J + 15 new single-hunk Java vulns. We read the
    repo's metadata JSON(s) under ``--vjbench``. With ``--include-trans`` we also
    emit VJBench-trans transformed variants (memorization control), flagged
    transformed=True.

`semgrep_covered` is set True iff the bug's CWE appears in config/cwe_focus.yaml
(the AND-gate's "covered" stratum).

PUBLIC DATA ONLY. The manifest (and data/) is .gitignored.

Example:
    python -m data.prep.build_eval_set --vul4j-ids data/raw/vul4j_ids.txt \
        --vjbench data/raw/vjbench/ --out data/eval/manifest.jsonl \
        [--cwe-focus config/cwe_focus.yaml] [--include-trans]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

try:
    from data.prep.schemas import EvalManifestEntry
except Exception:  # pragma: no cover - direct-run fallback.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from data.prep.schemas import EvalManifestEntry

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional at import time.
    yaml = None  # Handled with a clear error in load_cwe_focus.


class Vul4JNotInstalled(RuntimeError):
    """Raised when the `vul4j` CLI is needed but not on PATH."""


# --- cwe focus ---------------------------------------------------------------

def load_cwe_focus(path: str) -> Set[str]:
    """Load the set of focus CWE ids from config/cwe_focus.yaml.

    Returns the uppercased CWE ids under ``cwes[].id``. If the file is missing or
    PyYAML is absent, returns an empty set (all bugs become semgrep_covered=False)
    after warning -- the manifest is still produced.
    """
    p = Path(path)
    if not p.exists():
        print(f"[build_eval_set] WARNING: cwe-focus not found: {path}", file=sys.stderr)
        return set()
    if yaml is None:
        print(
            "[build_eval_set] WARNING: PyYAML not installed; cannot read cwe-focus "
            "(pip install pyyaml==6.0.2). Treating all bugs as uncovered.",
            file=sys.stderr,
        )
        return set()
    try:
        doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        print(f"[build_eval_set] WARNING: bad cwe-focus YAML {path}: {exc}", file=sys.stderr)
        return set()
    cwes = doc.get("cwes", []) or []
    out: Set[str] = set()
    for entry in cwes:
        if isinstance(entry, dict) and entry.get("id"):
            out.add(str(entry["id"]).strip().upper())
    return out


# --- vul4j metadata ----------------------------------------------------------

def _vul4j_info(bug_id: str, timeout: int = 60) -> Optional[Dict[str, Any]]:
    """Call ``vul4j info <id>`` and parse JSON. None on any failure (graceful)."""
    try:
        cp = subprocess.run(
            ["vul4j", "info", "-i", bug_id],  # upstream `info` requires -i/--id
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise Vul4JNotInstalled(
            "vul4j CLI not found on PATH. Install Vul4J (Docker image "
            "'tuhhsoftsec/vul4j') or supply --vul4j-meta with cached metadata."
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        print(f"[build_eval_set] WARNING: vul4j info {bug_id} failed: {exc}", file=sys.stderr)
        return None
    if cp.returncode != 0:
        print(
            f"[build_eval_set] WARNING: vul4j info {bug_id} exit {cp.returncode}: "
            f"{cp.stderr.strip()[:200]}",
            file=sys.stderr,
        )
        return None
    out = cp.stdout.strip()
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        # Some vul4j builds print human text; fall back to a tolerant line parse.
        return _parse_vul4j_text(out)


def _parse_vul4j_text(text: str) -> Dict[str, Any]:
    """Best-effort parse of non-JSON ``vul4j info`` output into a dict."""
    d: Dict[str, Any] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        d[k.strip().lower().replace(" ", "_")] = v.strip()
    return d


def _norm_cwe(raw: Any) -> str:
    """Normalize a CWE value to 'CWE-<n>' or '' if absent."""
    if not raw:
        return ""
    s = str(raw).strip().upper()
    if not s:
        return ""
    if s.startswith("CWE-"):
        return s
    if s.startswith("CWE"):
        return "CWE-" + s[3:].lstrip("-_")
    if s.isdigit():
        return "CWE-" + s
    return s


def _coerce_pov_tests(meta: Dict[str, Any]) -> List[str]:
    """Extract PoV/failing test ids from heterogeneous metadata."""
    for key in ("failing_tests", "pov_tests", "tests", "reproduce_tests"):
        v = meta.get(key)
        if isinstance(v, list) and v:
            return [str(x) for x in v]
        if isinstance(v, str) and v:
            return [t.strip() for t in v.split(",") if t.strip()]
    return []


def entry_from_vul4j_meta(bug_id: str, meta: Dict[str, Any], focus: Set[str]) -> EvalManifestEntry:
    """Build an EvalManifestEntry from a Vul4J metadata dict (any schema flavor)."""
    cwe = _norm_cwe(meta.get("cwe_id") or meta.get("cwe"))
    project = str(meta.get("project") or meta.get("project_name") or "")
    vfile = str(
        meta.get("vulnerable_file")
        or meta.get("human_patch_file")
        or meta.get("file")
        or ""
    )
    human_ref = str(
        meta.get("human_patch")
        or meta.get("fixing_commit_hash")
        or meta.get("revision")
        or ""
    )
    return EvalManifestEntry(
        id=bug_id,
        project=project,
        cwe=cwe,
        source="vul4j",
        vulnerable_file=vfile,
        pov_tests=_coerce_pov_tests(meta),
        human_patch_ref=human_ref,
        semgrep_covered=(cwe.upper() in focus) if cwe else False,
        transformed=False,
    )


def load_vul4j_meta_cache(path: Optional[str]) -> Dict[str, Dict[str, Any]]:
    """Load an optional cached Vul4J metadata JSON: {id: {meta...}}.

    Lets the manifest be built offline (no vul4j CLI). Returns {} if no path /
    missing file.
    """
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        print(f"[build_eval_set] WARNING: --vul4j-meta not found: {path}", file=sys.stderr)
        return {}
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"[build_eval_set] WARNING: bad --vul4j-meta JSON: {exc}", file=sys.stderr)
        return {}
    return doc if isinstance(doc, dict) else {}


def build_vul4j_entries(
    ids_path: str, focus: Set[str], meta_cache: Dict[str, Dict[str, Any]]
) -> List[EvalManifestEntry]:
    """Build entries for each id in the ``--vul4j-ids`` file.

    Resolution order per id: cached metadata -> ``vul4j info`` -> minimal stub.
    Never raises on a single id; missing metadata yields a stub entry that the
    eval harness can still attempt (and report incomplete).
    """
    p = Path(ids_path)
    if not p.exists():
        raise FileNotFoundError(f"--vul4j-ids file not found: {ids_path}")
    ids = [
        ln.strip()
        for ln in p.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    cli_missing_warned = False
    out: List[EvalManifestEntry] = []
    for bug_id in ids:
        meta = meta_cache.get(bug_id)
        if meta is None:
            try:
                meta = _vul4j_info(bug_id)
            except Vul4JNotInstalled as exc:
                if not cli_missing_warned:
                    print(f"[build_eval_set] WARNING: {exc}", file=sys.stderr)
                    cli_missing_warned = True
                meta = None
        if meta:
            out.append(entry_from_vul4j_meta(bug_id, meta, focus))
        else:
            out.append(
                EvalManifestEntry(
                    id=bug_id,
                    project="",
                    cwe="",
                    source="vul4j",
                    vulnerable_file="",
                    pov_tests=[],
                    human_patch_ref="",
                    semgrep_covered=False,
                    transformed=False,
                )
            )
    return out


# --- vjbench metadata --------------------------------------------------------

def _iter_vjbench_records(vjbench_dir: str) -> List[Dict[str, Any]]:
    """Collect VJBench/llm-vul metadata records from JSON/JSONL under the dir.

    The llm-vul repo ships per-vuln metadata; we accept either a single
    ``*.json`` mapping/list or many per-bug JSON files. Each record should carry a
    bug id, project, cwe, vulnerable file, and failing/PoV tests under common key
    aliases. Unknown shapes are skipped with a warning.
    """
    root = Path(vjbench_dir)
    if not root.exists():
        print(
            f"[build_eval_set] WARNING: --vjbench dir not found ({vjbench_dir}); "
            "skipping VJBench (Vul4J-only manifest is still written).",
            file=sys.stderr,
        )
        return []
    records: List[Dict[str, Any]] = []
    for fp in sorted(root.rglob("*.json")) + sorted(root.rglob("*.jsonl")):
        try:
            text = fp.read_text(encoding="utf-8")
        except Exception as exc:  # pragma: no cover
            print(f"[build_eval_set] WARNING: cannot read {fp}: {exc}", file=sys.stderr)
            continue
        if fp.suffix == ".jsonl":
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        else:
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(doc, list):
                records.extend([x for x in doc if isinstance(x, dict)])
            elif isinstance(doc, dict):
                # Either a single record, or a {id: record} map.
                if any(k in doc for k in ("id", "vul_id", "bug_id", "name")):
                    records.append(doc)
                else:
                    for k, v in doc.items():
                        if isinstance(v, dict):
                            v.setdefault("id", k)
                            records.append(v)
    return records


def _vjbench_id(rec: Dict[str, Any]) -> str:
    for k in ("id", "vul_id", "bug_id", "name"):
        if rec.get(k):
            return str(rec[k])
    return ""


def entry_from_vjbench(rec: Dict[str, Any], focus: Set[str], transformed: bool) -> Optional[EvalManifestEntry]:
    """Build an EvalManifestEntry from one VJBench/llm-vul record, or None."""
    bug_id = _vjbench_id(rec)
    if not bug_id:
        return None
    cwe = _norm_cwe(rec.get("cwe") or rec.get("cwe_id"))
    project = str(rec.get("project") or rec.get("repo") or "")
    vfile = str(rec.get("vulnerable_file") or rec.get("file") or rec.get("buggy_file") or "")
    pov = _coerce_pov_tests(rec)
    human_ref = str(rec.get("human_patch") or rec.get("fix_commit") or rec.get("patch_ref") or "")
    return EvalManifestEntry(
        id=bug_id if not transformed else f"{bug_id}-trans",
        project=project,
        cwe=cwe,
        source="vjbench",
        vulnerable_file=vfile,
        pov_tests=pov,
        human_patch_ref=human_ref,
        semgrep_covered=(cwe.upper() in focus) if cwe else False,
        transformed=transformed,
    )


def build_vjbench_entries(
    vjbench_dir: str, focus: Set[str], include_trans: bool
) -> List[EvalManifestEntry]:
    """Build VJBench entries; optionally include VJBench-trans variants.

    A record is treated as a transformed variant if it carries a truthy
    ``transformed``/``is_trans`` flag or lives under a path containing 'trans'.
    Non-transformed records are always emitted; transformed ones only when
    ``include_trans``.
    """
    records = _iter_vjbench_records(vjbench_dir)
    out: List[EvalManifestEntry] = []
    for rec in records:
        is_trans = bool(rec.get("transformed") or rec.get("is_trans"))
        if is_trans and not include_trans:
            continue
        entry = entry_from_vjbench(rec, focus, transformed=is_trans)
        if entry:
            out.append(entry)
    return out


# --- write -------------------------------------------------------------------

def write_manifest(path: str, entries: List[EvalManifestEntry]) -> None:
    """Write entries to a JSONL manifest, deduping by id (first wins)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    seen: Set[str] = set()
    with p.open("w", encoding="utf-8") as fh:
        for e in entries:
            if e.id in seen:
                continue
            seen.add(e.id)
            fh.write(json.dumps(e.to_dict(), ensure_ascii=False) + "\n")


# --- CLI ---------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="build_eval_set",
        description="Assemble the Vul4J/VJBench eval manifest (ids, cwe, source).",
    )
    ap.add_argument("--vul4j-ids", default=None, help="Text file of Vul4J ids (one per line).")
    ap.add_argument(
        "--vul4j-meta",
        default=None,
        help="Optional cached Vul4J metadata JSON {id: {...}} for offline builds.",
    )
    ap.add_argument("--vjbench", default=None, help="Dir of VJBench/llm-vul metadata JSON(L).")
    ap.add_argument("--out", required=True, help="Output manifest JSONL path.")
    ap.add_argument(
        "--cwe-focus",
        default="config/cwe_focus.yaml",
        help="cwe_focus.yaml that defines the semgrep-covered stratum.",
    )
    ap.add_argument(
        "--include-trans",
        action="store_true",
        help="Also emit VJBench-trans transformed variants (memorization control).",
    )
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. Returns 0 on success, 1 on fatal input error."""
    ap = build_arg_parser()
    args = ap.parse_args(argv)

    if not args.vul4j_ids and not args.vjbench:
        print(
            "[build_eval_set] ERROR: provide at least one of --vul4j-ids / --vjbench.",
            file=sys.stderr,
        )
        return 1

    focus = load_cwe_focus(args.cwe_focus)

    entries: List[EvalManifestEntry] = []

    if args.vul4j_ids:
        try:
            cache = load_vul4j_meta_cache(args.vul4j_meta)
            entries.extend(build_vul4j_entries(args.vul4j_ids, focus, cache))
        except FileNotFoundError as exc:
            print(f"[build_eval_set] ERROR: {exc}", file=sys.stderr)
            return 1

    if args.vjbench:
        try:
            entries.extend(build_vjbench_entries(args.vjbench, focus, args.include_trans))
        except FileNotFoundError as exc:
            print(f"[build_eval_set] ERROR: {exc}", file=sys.stderr)
            return 1

    if not entries:
        print("[build_eval_set] ERROR: no eval entries assembled.", file=sys.stderr)
        return 1

    write_manifest(args.out, entries)

    n_vul4j = sum(1 for e in entries if e.source == "vul4j")
    n_vjb = sum(1 for e in entries if e.source == "vjbench" and not e.transformed)
    n_trans = sum(1 for e in entries if e.transformed)
    n_cov = sum(1 for e in entries if e.semgrep_covered)
    print(
        f"[build_eval_set] wrote {args.out}: total={len(entries)} "
        f"vul4j={n_vul4j} vjbench={n_vjb} vjbench-trans={n_trans} "
        f"semgrep_covered={n_cov}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

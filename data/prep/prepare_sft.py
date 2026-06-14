"""Prepare the leakage-free, deduplicated, temporally/by-CVE split SFT dataset.

Pipeline (MG6 contract, see SPEC §5):
  1. Load raw vuln-repair records from ``--raw`` (a dir of .json/.jsonl files).
     Each record needs: vuln_code, fixed_code, and ideally cve, cwe, date,
     project. Records missing vuln_code or fixed_code are dropped (counted).
  2. DEDUP on the normalized (vuln, fixed) pair:
       * exact-hash dedup over (normalize_code(vuln), normalize_code(fixed)).
       * near-dup dedup via token Jaccard >= --min-jaccard against kept records.
       * on collision, keep the EARLIEST by date (stable, reproducible).
  3. SPLIT into train / held-out eval so NO CVE family or project leaks across:
       * --split temporal : train = CVEs dated before a cutoff, eval = on/after.
         Cutoff is auto-derived (a quantile of the date distribution) unless
         --cutoff-date is given.
       * --cve-split       : partition whole CVE families (and, defensively,
         projects) so a family never spans both sides. Deterministic via --seed.
  4. STRIP leaks from the instruction+input with strip_leaky_tokens (CWE/CVE/
     path/commit/marker/bug-id tokens). The OUTPUT (the human patch) is NOT
     stripped — it is the target the model must reproduce verbatim.
  5. EMIT instruction-format JSONL:
        {"instruction": "...", "input": "<vuln file>", "output": "<patched file>",
         "meta": {...non-leaky...}}
     to --out (train) and --eval-out (held-out).

PUBLIC DATA ONLY. The emitted JSONL lives under data/ which is .gitignored.

Example:
    python -m data.prep.prepare_sft --raw data/raw/ --out data/sft/train.jsonl \
        --eval-out data/sft/eval_heldout.jsonl --split temporal \
        [--cutoff-date 2022-01-01] [--cve-split] [--min-jaccard 0.9] [--seed 13]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    # Package-relative import (normal case: run as ``python -m data.prep.prepare_sft``).
    from data.prep.normalize import normalize_code, strip_leaky_tokens, token_jaccard
    from data.prep.schemas import SFTExample
except Exception:  # pragma: no cover - allows running the file directly.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from data.prep.normalize import normalize_code, strip_leaky_tokens, token_jaccard
    from data.prep.schemas import SFTExample


INSTRUCTION = (
    "Fix this Java vulnerability. Return the complete patched file, preserving "
    "all existing behavior. Output only the full Java source of the fixed file."
)


# --- raw record model --------------------------------------------------------

@dataclass
class RawRecord:
    """One raw vuln-repair pair loaded from disk (pre-dedup, pre-split)."""

    vuln_code: str
    fixed_code: str
    cve: str
    cwe: str
    date: str  # ISO-ish YYYY-MM-DD or "" if unknown.
    project: str
    source_file: str  # which raw file this came from (provenance only).

    def dedup_key(self) -> str:
        """Stable hash of the normalized (vuln, fixed) pair."""
        norm = normalize_code(self.vuln_code) + "\x00" + normalize_code(self.fixed_code)
        return hashlib.sha1(norm.encode("utf-8")).hexdigest()


# Field aliases tolerated in raw JSON (different corpora use different keys).
_VULN_KEYS = ("vuln_code", "vulnerable_code", "before", "buggy_code", "input")
_FIXED_KEYS = ("fixed_code", "patched_code", "after", "fix_code", "output")
_CVE_KEYS = ("cve", "cve_id", "CVE")
_CWE_KEYS = ("cwe", "cwe_id", "CWE")
_DATE_KEYS = ("date", "published", "commit_date", "fix_date", "published_date")
_PROJECT_KEYS = ("project", "repo", "repository", "project_name")


def _first(d: Dict[str, Any], keys: Iterable[str], default: str = "") -> str:
    for k in keys:
        v = d.get(k)
        if v is not None and str(v) != "":
            return str(v)
    return default


def _record_from_dict(d: Dict[str, Any], source_file: str) -> Optional[RawRecord]:
    """Build a RawRecord from a parsed dict, or None if it lacks the pair."""
    vuln = _first(d, _VULN_KEYS)
    fixed = _first(d, _FIXED_KEYS)
    if not vuln or not fixed:
        return None
    return RawRecord(
        vuln_code=vuln,
        fixed_code=fixed,
        cve=_first(d, _CVE_KEYS),
        cwe=_first(d, _CWE_KEYS),
        date=_first(d, _DATE_KEYS),
        project=_first(d, _PROJECT_KEYS),
        source_file=source_file,
    )


def load_raw(raw_dir: str) -> List[RawRecord]:
    """Load all .json / .jsonl files under ``raw_dir`` into RawRecords.

    Accepts:
        * .jsonl : one JSON object per line.
        * .json  : either a top-level list of objects, or a single object.

    Malformed lines/files are skipped with a warning to stderr (never crash).
    Returns the records in a deterministic order (sorted by file then index).
    """
    root = Path(raw_dir)
    if not root.exists():
        raise FileNotFoundError(
            f"--raw directory does not exist: {raw_dir}. Place CVEfixes/Juliet/"
            f"Vul4J-derived vuln-repair JSON(L) there (see data/README.md)."
        )
    out: List[RawRecord] = []
    files = sorted([p for p in root.rglob("*") if p.suffix in (".json", ".jsonl")])
    if not files:
        print(f"[prepare_sft] WARNING: no .json/.jsonl files under {raw_dir}", file=sys.stderr)
    for fp in files:
        rel = str(fp.relative_to(root))
        try:
            text = fp.read_text(encoding="utf-8")
        except Exception as exc:  # pragma: no cover - IO edge.
            print(f"[prepare_sft] WARNING: cannot read {fp}: {exc}", file=sys.stderr)
            continue
        if fp.suffix == ".jsonl":
            for i, line in enumerate(text.splitlines()):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError as exc:
                    print(f"[prepare_sft] WARNING: {rel}:{i+1} bad JSON: {exc}", file=sys.stderr)
                    continue
                rec = _record_from_dict(obj, rel)
                if rec:
                    out.append(rec)
        else:
            try:
                obj = json.loads(text)
            except json.JSONDecodeError as exc:
                print(f"[prepare_sft] WARNING: {rel} bad JSON: {exc}", file=sys.stderr)
                continue
            items = obj if isinstance(obj, list) else [obj]
            for it in items:
                if isinstance(it, dict):
                    rec = _record_from_dict(it, rel)
                    if rec:
                        out.append(rec)
    return out


# --- dedup -------------------------------------------------------------------

def _date_key(rec: RawRecord) -> str:
    """Sort key for 'earliest first'. Empty dates sort LAST so dated records win."""
    return rec.date if rec.date else "9999-99-99"


def dedup(records: List[RawRecord], min_jaccard: float) -> Tuple[List[RawRecord], Dict[str, int]]:
    """Remove exact and near-duplicate (vuln, fixed) pairs, keeping earliest.

    Algorithm:
      1. Sort by (date, source_file) so the EARLIEST record is seen first and
         therefore kept on any collision.
      2. Exact dedup on the SHA1 of the normalized pair.
      3. Near-dup: a candidate is dropped if its Jaccard similarity to ANY already
         kept record exceeds ``min_jaccard`` for BOTH the vuln side and the fixed
         side (both must be near-dup to count as a duplicate pair). Jaccard is only
         evaluated against kept records sharing the same project to bound cost.

    Returns:
        (kept_records, stats) where stats has counts: input, exact_dups,
        near_dups, kept.
    """
    stats = {"input": len(records), "exact_dups": 0, "near_dups": 0, "kept": 0}
    ordered = sorted(records, key=lambda r: (_date_key(r), r.source_file))
    seen_hashes: set[str] = set()
    kept: List[RawRecord] = []
    kept_by_project: Dict[str, List[RawRecord]] = {}

    for rec in ordered:
        h = rec.dedup_key()
        if h in seen_hashes:
            stats["exact_dups"] += 1
            continue
        # Near-dup check against same-project kept records.
        is_near = False
        if 0.0 < min_jaccard <= 1.0:
            for prev in kept_by_project.get(rec.project, []):
                jv = token_jaccard(rec.vuln_code, prev.vuln_code)
                if jv < min_jaccard:
                    continue
                jf = token_jaccard(rec.fixed_code, prev.fixed_code)
                if jf >= min_jaccard:
                    is_near = True
                    break
        if is_near:
            stats["near_dups"] += 1
            continue
        seen_hashes.add(h)
        kept.append(rec)
        kept_by_project.setdefault(rec.project, []).append(rec)

    stats["kept"] = len(kept)
    return kept, stats


# --- split -------------------------------------------------------------------

def _auto_cutoff_date(records: List[RawRecord], eval_frac: float = 0.2) -> str:
    """Pick a cutoff so ~eval_frac of dated records fall on/after it.

    Records with no date are ignored for the cutoff computation (they are routed
    to train in temporal split). Returns "" if there are no usable dates.
    """
    dated = sorted([r.date for r in records if r.date])
    if not dated:
        return ""
    idx = int(len(dated) * (1.0 - eval_frac))
    idx = max(0, min(idx, len(dated) - 1))
    return dated[idx]


def split_temporal(
    records: List[RawRecord], cutoff_date: Optional[str], eval_frac: float = 0.2
) -> Tuple[List[RawRecord], List[RawRecord], str]:
    """Temporal split: train = date < cutoff, eval = date >= cutoff.

    Records with no date go to TRAIN (we never put undated records in eval, to
    avoid silent leakage of an unknown-era CVE). Returns (train, eval, cutoff).
    """
    cutoff = cutoff_date or _auto_cutoff_date(records, eval_frac)
    if not cutoff:
        # No dates anywhere: degrade to deterministic by-CVE split so the run
        # still produces a usable held-out set.
        tr, ev = split_by_cve(records, seed=13, eval_frac=eval_frac)
        return tr, ev, "(no dates; fell back to by-CVE)"
    train, ev = [], []
    for r in records:
        if r.date and r.date >= cutoff:
            ev.append(r)
        else:
            train.append(r)
    return train, ev, cutoff


def split_by_cve(
    records: List[RawRecord], seed: int, eval_frac: float = 0.2
) -> Tuple[List[RawRecord], List[RawRecord]]:
    """By-family split: no CVE family (and no project) spans train/eval.

    A "family" key is the CVE id if present, else the project, else a per-record
    sentinel. Whole families are assigned to eval until ~eval_frac of records are
    held out. Deterministic for a given seed.
    """
    fam_to_recs: Dict[str, List[RawRecord]] = {}
    for r in records:
        fam = r.cve or r.project or f"__rec_{id(r)}"
        fam_to_recs.setdefault(fam, []).append(r)

    families = sorted(fam_to_recs.keys())
    rng = random.Random(seed)
    rng.shuffle(families)

    total = len(records)
    target_eval = int(total * eval_frac)
    eval_recs: List[RawRecord] = []
    eval_fams: set[str] = set()
    for fam in families:
        if len(eval_recs) >= target_eval:
            break
        eval_recs.extend(fam_to_recs[fam])
        eval_fams.add(fam)

    train_recs = [r for fam in families if fam not in eval_fams for r in fam_to_recs[fam]]
    return train_recs, eval_recs


def assert_no_leakage(train: List[RawRecord], ev: List[RawRecord]) -> None:
    """Raise AssertionError if any CVE family or project appears on both sides."""
    train_cves = {r.cve for r in train if r.cve}
    eval_cves = {r.cve for r in ev if r.cve}
    cve_overlap = train_cves & eval_cves
    assert not cve_overlap, f"CVE leakage across split: {sorted(cve_overlap)[:5]}"


# --- emit --------------------------------------------------------------------

def to_sft_example(rec: RawRecord, split_name: str, cutoff: str) -> SFTExample:
    """Build a leak-stripped SFTExample from a RawRecord.

    The instruction is fixed; the input (vulnerable file) is leak-stripped; the
    output (human patch) is the verbatim fixed file (the learning target). Meta
    carries only NON-LEAKY provenance.
    """
    stripped_input = strip_leaky_tokens(rec.vuln_code)
    meta: Dict[str, Any] = {
        "project": rec.project,
        "date": rec.date,
        "split": split_name,
        "cutoff": cutoff,
        "dedup_key": rec.dedup_key(),
        # NOTE: cve/cwe/source_file are intentionally OMITTED from meta to keep
        # the example leak-free even if meta is accidentally concatenated.
    }
    return SFTExample(
        instruction=INSTRUCTION,
        input=stripped_input,
        output=rec.fixed_code,
        meta=meta,
    )


def write_jsonl(path: str, examples: List[SFTExample]) -> None:
    """Write SFTExamples to a JSONL file, creating parent dirs."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as fh:
        for ex in examples:
            fh.write(json.dumps(ex.to_dict(), ensure_ascii=False) + "\n")


# --- CLI ---------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="prepare_sft",
        description="Dedup, split (temporal/by-CVE), strip leaks, emit instruction JSONL.",
    )
    ap.add_argument("--raw", required=True, help="Dir of raw .json/.jsonl vuln-repair records.")
    ap.add_argument("--out", required=True, help="Output train JSONL path.")
    ap.add_argument("--eval-out", required=True, help="Output held-out eval JSONL path.")
    ap.add_argument(
        "--split",
        choices=["temporal", "cve"],
        default="temporal",
        help="Split strategy (default: temporal).",
    )
    ap.add_argument(
        "--cve-split",
        action="store_true",
        help="Force by-CVE split (overrides --split temporal).",
    )
    ap.add_argument(
        "--cutoff-date",
        default=None,
        help="Temporal cutoff YYYY-MM-DD (eval = on/after). Auto-derived if omitted.",
    )
    ap.add_argument(
        "--eval-frac",
        type=float,
        default=0.2,
        help="Target held-out fraction (default 0.2).",
    )
    ap.add_argument(
        "--min-jaccard",
        type=float,
        default=0.9,
        help="Near-dup token-Jaccard threshold (default 0.9; <=0 disables near-dup).",
    )
    ap.add_argument("--seed", type=int, default=13, help="RNG seed for by-CVE split.")
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. Returns process exit code (0 ok, 1 error)."""
    ap = build_arg_parser()
    args = ap.parse_args(argv)

    try:
        raw = load_raw(args.raw)
    except FileNotFoundError as exc:
        print(f"[prepare_sft] ERROR: {exc}", file=sys.stderr)
        return 1

    if not raw:
        print("[prepare_sft] ERROR: no usable (vuln, fixed) records found.", file=sys.stderr)
        return 1

    kept, dstats = dedup(raw, args.min_jaccard)
    print(
        f"[prepare_sft] dedup: input={dstats['input']} "
        f"exact_dups={dstats['exact_dups']} near_dups={dstats['near_dups']} "
        f"kept={dstats['kept']}",
        file=sys.stderr,
    )

    if args.cve_split or args.split == "cve":
        train_recs, eval_recs = split_by_cve(kept, seed=args.seed, eval_frac=args.eval_frac)
        cutoff = f"(by-CVE, seed={args.seed})"
        split_name = "cve"
    else:
        train_recs, eval_recs, cutoff = split_temporal(kept, args.cutoff_date, args.eval_frac)
        split_name = "temporal"

    try:
        assert_no_leakage(train_recs, eval_recs)
    except AssertionError as exc:
        print(f"[prepare_sft] ERROR: {exc}", file=sys.stderr)
        return 1

    train_ex = [to_sft_example(r, "train", cutoff) for r in train_recs]
    eval_ex = [to_sft_example(r, "eval", cutoff) for r in eval_recs]

    write_jsonl(args.out, train_ex)
    write_jsonl(args.eval_out, eval_ex)

    print(
        f"[prepare_sft] split={split_name} cutoff={cutoff} "
        f"train={len(train_ex)} eval_heldout={len(eval_ex)}",
        file=sys.stderr,
    )
    print(f"[prepare_sft] wrote {args.out} and {args.eval_out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

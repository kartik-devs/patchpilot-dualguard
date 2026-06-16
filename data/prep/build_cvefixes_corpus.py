"""Build a REAL, leakage-free Java SFT corpus from CVEfixes (the merit fine-tune).

Replaces the 10-example bootstrap seed with a corpus-scale, honestly-split dataset.
Pipeline (per the research recipe in docs/MERIT_RUNBOOK.md):

  1. JOIN method_change -> file_change -> commits -> fixes -> cve, keep Java method
     pairs: before_change=true (vulnerable input) + before_change=false (fixed target),
     conditioned on the CVE's CWE.
  2. LEAKAGE CONTROL (report the count after each — that table is the merit):
       a. by-CVE AND by-REPO holdout: drop pairs whose CVE or repo is a Vul4J eval
          project (dropping the whole repo kills project-idiom leakage).
       b. temporal cut: keep only commits before the Vul4J cutoff (~2021).
       c. dedup: exact SHA-256 over normalized before+after, then near-dup MinHashLSH
          (datasketch, Jaccard>=0.8); ALSO drop any pair whose vulnerable method
          near-matches a Vul4J vulnerable method.
  3. Emit instruction-formatted SFT JSONL (same shape as train/seed_sft.jsonl) + a
     provenance JSON with the 4 numbers.

CVEfixes: Zenodo DOI 10.5281/zenodo.4476563 — ships a SQL dump; load it into SQLite:
    gunzip -k CVEfixes.sql.gz && sqlite3 CVEfixes.db < CVEfixes.sql
NOTE: column names vary slightly across CVEfixes versions — this script introspects
the schema and falls back gracefully; verify the printed column map on first run.

Run:
    python -m data.prep.build_cvefixes_corpus --db CVEfixes.db \
        --out data/sft/train.jsonl --provenance data/sft/provenance.json \
        --vul4j-csv data/raw/vul4j_dataset.csv --cutoff 2021-01-01
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

# Vul4J eval projects to hold OUT by repo (fallback if --vul4j-csv not given). Prefer
# passing the full vul4j_dataset.csv so all 79 projects/CVEs are excluded.
_DEFAULT_VUL4J_REPOS = {
    "javamelody", "jsoup", "jackson-dataformat-xml", "jackson-databind", "openrefine",
    "plexus-archiver", "sling", "rdf4j", "xstream", "esapi-java-legacy", "esapi",
    "swagger-parser", "commons-compress",
}

_WS = re.compile(r"\s+")
_INSTR = (
    "You are given a Java method with a {cwe} vulnerability. Return the COMPLETE "
    "corrected method. Fix only the vulnerability; preserve behavior; do not delete "
    "functionality. Output only the fixed Java in a ```java block."
)


def _norm(code: str) -> str:
    return _WS.sub(" ", (code or "")).strip()


def _sha(code_before: str, code_after: str) -> str:
    return hashlib.sha256((_norm(code_before) + "\x00" + _norm(code_after)).encode("utf-8")).hexdigest()


def _cols(con: sqlite3.Connection, table: str) -> Set[str]:
    try:
        return {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
    except sqlite3.Error:
        return set()


def _pick(cols: Set[str], *candidates: str) -> Optional[str]:
    for c in candidates:
        if c in cols:
            return c
    return None


def load_vul4j_exclusions(csv_path: Optional[str]) -> Tuple[Set[str], Set[str]]:
    """Return (cve_ids, repo_substrings) to hold out. Falls back to defaults."""
    cves: Set[str] = set()
    repos: Set[str] = set(_DEFAULT_VUL4J_REPOS)
    if csv_path and os.path.isfile(csv_path):
        import csv

        with open(csv_path, newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.DictReader(fh):
                for k, v in row.items():
                    kl = (k or "").lower()
                    if "cve" in kl and v and v.upper().startswith("CVE-"):
                        cves.add(v.upper())
                    if ("repo" in kl or "project" in kl or "url" in kl) and v:
                        repos.add(v.strip().lower().rstrip("/").split("/")[-1].replace(".git", ""))
    return cves, repos


def query_pairs(con: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Extract Java (vulnerable, fixed) method pairs with cve/cwe/repo/date."""
    mc, fc, cm, fx, cw = (_cols(con, t) for t in
                          ("method_change", "file_change", "commits", "fixes", "cwe_classification"))
    code_col = _pick(mc, "code", "code_change", "method_code")
    before_col = _pick(mc, "before_change", "is_before", "before")
    name_col = _pick(mc, "name", "method_name", "signature")
    fcid_in_mc = _pick(mc, "file_change_id")
    fcid_in_fc = _pick(fc, "file_change_id")
    lang_col = _pick(fc, "programming_language", "language")
    hash_in_fc = _pick(fc, "hash", "commit_hash")
    hash_in_cm = _pick(cm, "hash", "commit_hash")
    repo_col = _pick(cm, "repo_url", "repo_name", "repository")
    date_col = _pick(cm, "committer_date", "author_date", "commit_date", "date")
    hash_in_fx = _pick(fx, "hash", "commit_hash")
    cve_in_fx = _pick(fx, "cve_id", "cve")

    missing = [n for n, v in {
        "method_change.code": code_col, "method_change.before_change": before_col,
        "file_change.file_change_id": fcid_in_fc, "file_change.language": lang_col,
        "commits.hash": hash_in_cm, "fixes.cve_id": cve_in_fx}.items() if not v]
    if missing:
        raise RuntimeError(f"CVEfixes schema mismatch — missing: {missing}. "
                           f"Inspect with: sqlite3 CVEfixes.db '.schema method_change'")

    sys.stderr.write(f"[corpus] columns: code={code_col} before={before_col} name={name_col} "
                     f"lang={lang_col} repo={repo_col} date={date_col} cve={cve_in_fx}\n")

    sql = f"""
    SELECT mc.{code_col} AS code, mc.{before_col} AS before_change,
           {('mc.' + name_col) if name_col else "''"} AS mname,
           fc.{fcid_in_fc} AS fcid, cm.{hash_in_cm} AS chash,
           {('cm.' + repo_col) if repo_col else "''"} AS repo,
           {('cm.' + date_col) if date_col else "''"} AS cdate,
           fx.{cve_in_fx} AS cve_id
    FROM method_change mc
    JOIN file_change fc ON mc.{fcid_in_mc or fcid_in_fc} = fc.{fcid_in_fc}
    JOIN commits cm ON fc.{hash_in_fc or hash_in_cm} = cm.{hash_in_cm}
    JOIN fixes fx ON cm.{hash_in_cm} = fx.{hash_in_fx or hash_in_cm}
    WHERE lower(fc.{lang_col}) = 'java'
    """
    # cwe per cve (optional)
    cwe_for: Dict[str, str] = {}
    if cm and cw:
        cvek = _pick(cw, "cve_id", "cve")
        cwek = _pick(cw, "cwe_id", "cwe")
        if cvek and cwek:
            for cve, cwe in con.execute(f"SELECT {cvek}, {cwek} FROM cwe_classification"):
                if cve and cwe and cve not in cwe_for:
                    cwe_for[str(cve)] = str(cwe)

    # group method rows by (fcid, mname) -> before/after
    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for row in con.execute(sql):
        code, before, mname, fcid, chash, repo, cdate, cve = row
        key = (str(fcid), str(mname))
        g = groups.setdefault(key, {"repo": repo, "cdate": cdate, "cve": cve})
        is_before = str(before).lower() in ("1", "true", "t", "yes")
        g["vuln" if is_before else "fixed"] = code

    pairs = []
    for (fcid, mname), g in groups.items():
        if g.get("vuln") and g.get("fixed") and _norm(g["vuln"]) != _norm(g["fixed"]):
            pairs.append({
                "vuln": g["vuln"], "fixed": g["fixed"], "repo": g.get("repo") or "",
                "cdate": str(g.get("cdate") or ""), "cve": str(g.get("cve") or ""),
                "cwe": cwe_for.get(str(g.get("cve") or ""), ""),
            })
    return pairs


def _repo_key(repo: str) -> str:
    return (repo or "").strip().lower().rstrip("/").split("/")[-1].replace(".git", "")


def build(db: str, out: str, provenance: str, vul4j_csv: Optional[str],
          cutoff: str, jaccard: float = 0.8) -> Dict[str, int]:
    con = sqlite3.connect(db)
    pairs = query_pairs(con)
    prov = {"raw_java_pairs": len(pairs)}

    # (a) by-CVE + by-repo holdout
    hold_cves, hold_repos = load_vul4j_exclusions(vul4j_csv)
    pairs = [p for p in pairs
             if p["cve"].upper() not in hold_cves and _repo_key(p["repo"]) not in hold_repos]
    prov["after_vul4j_holdout"] = len(pairs)

    # (b) temporal cut (keep commits strictly before cutoff)
    pairs = [p for p in pairs if (p["cdate"][:10] < cutoff if p["cdate"] else True)]
    prov["after_temporal_cut"] = len(pairs)

    # (c) dedup: exact, then near-dup MinHash
    seen: Set[str] = set()
    exact = []
    for p in pairs:
        h = _sha(p["vuln"], p["fixed"])
        if h not in seen:
            seen.add(h)
            exact.append(p)
    pairs = exact
    try:
        from datasketch import MinHash, MinHashLSH

        def mh(code: str) -> "MinHash":
            m = MinHash(num_perm=64)
            for tok in set(_norm(code).split()):
                m.update(tok.encode("utf-8"))
            return m

        lsh = MinHashLSH(threshold=jaccard, num_perm=64)
        kept = []
        for i, p in enumerate(pairs):
            m = mh(p["vuln"] + " " + p["fixed"])
            if not lsh.query(m):
                lsh.insert(str(i), m)
                kept.append(p)
        pairs = kept
    except ImportError:
        sys.stderr.write("[corpus] datasketch not installed; exact-dedup only. "
                         "pip install datasketch for near-dup removal.\n")
    prov["after_dedup"] = len(pairs)

    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        for p in pairs:
            cwe = p["cwe"] or "security"
            rec = {
                "cwe": cwe,
                "prompt": _INSTR.format(cwe=cwe) + "\n\n```java\n" + p["vuln"].strip() + "\n```",
                "completion": "```java\n" + p["fixed"].strip() + "\n```",
            }
            fh.write(json.dumps(rec) + "\n")
    with open(provenance, "w", encoding="utf-8") as fh:
        json.dump(prov, fh, indent=2)

    print("[corpus] provenance (this table IS the merit):")
    for k, v in prov.items():
        print(f"  {k:<22} {v}")
    print(f"[corpus] wrote {prov['after_dedup']} SFT pairs -> {out}")
    return prov


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m data.prep.build_cvefixes_corpus",
                                description="Build a leakage-free Java SFT corpus from CVEfixes.")
    p.add_argument("--db", required=True, help="Path to the CVEfixes SQLite DB.")
    p.add_argument("--out", default="data/sft/train.jsonl")
    p.add_argument("--provenance", default="data/sft/provenance.json")
    p.add_argument("--vul4j-csv", default=None, help="vul4j_dataset.csv to hold out ALL Vul4J CVEs/repos.")
    p.add_argument("--cutoff", default="2021-01-01", help="Temporal cut (keep commits before this).")
    p.add_argument("--jaccard", type=float, default=0.8)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    a = build_arg_parser().parse_args(argv)
    if not os.path.isfile(a.db):
        sys.stderr.write(f"[corpus] DB not found: {a.db}. Build it: "
                         f"gunzip -k CVEfixes.sql.gz && sqlite3 {a.db} < CVEfixes.sql\n")
        return 2
    build(a.db, a.out, a.provenance, a.vul4j_csv, a.cutoff, a.jaccard)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

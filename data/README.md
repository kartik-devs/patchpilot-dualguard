# PatchPilot v2 "DualGuard" — Data

This directory holds the **inputs and derived artifacts** for SFT training and
evaluation. **Everything under `data/` is git-ignored** (see the repo root
`.gitignore`): no datasets, no `*.jsonl`, and nothing TCS-confidential is ever
committed. The code in `data/prep/` is committed; the data it produces is not.

> **PUBLIC-DATA-ONLY RULE.** Only publicly licensed, redistributable
> vulnerability-repair corpora may be placed here. Do **not** add proprietary,
> customer, or hackathon-confidential material (handbooks, problem-statement
> sheets, photos, decks). The data-prep pipeline additionally strips leakage
> tokens (CWE/CVE ids, file paths, commit hashes, fix/vuln markers, bug ids) from
> everything the model is trained to *read*, so it learns to repair from code
> structure rather than memorizing labels.

---

## Directory layout

```
data/
├── README.md                 # this file (committed)
├── prepare_sft.py            # committed shim -> data.prep.prepare_sft
├── build_eval_set.py         # committed shim -> data.prep.build_eval_set
├── prep/                     # committed code (MG6) — the canonical implementation
│   ├── prepare_sft.py        # dedup -> split -> strip leaks -> instruction JSONL
│   ├── build_eval_set.py     # assemble Vul4J/VJBench eval manifest
│   ├── normalize.py          # dedup-key + leak-strip helpers
│   └── schemas.py            # SFTExample / EvalManifestEntry dataclasses
├── raw/                      # (git-ignored) you populate this
│   ├── cvefixes/             # CVEfixes-derived vuln-repair JSON(L)
│   ├── juliet/               # Juliet-derived Java pairs
│   ├── vul4j_ids.txt         # one Vul4J id per line (e.g. VUL4J-10)
│   ├── vul4j_meta.json       # optional cached {id: metadata} for offline builds
│   └── vjbench/              # llm-vul / VJBench metadata JSON(L)
├── sft/                      # (git-ignored) prepare_sft.py outputs
│   ├── train.jsonl
│   └── eval_heldout.jsonl
└── eval/                     # (git-ignored) build_eval_set.py output
    └── manifest.jsonl
```

---

## Dataset sources & licenses

All training/eval data is public and redistributable under the licenses below.
Keep this table current if you add a corpus; **only add sources whose license
permits use and redistribution.**

| Source | What it provides | License | Notes |
|--------|------------------|---------|-------|
| **CVEfixes** | Real-world CVE fix commits (vuln → fixed file pairs) across many languages; we keep the Java subset. | **CC-BY 4.0** (dataset). Underlying code retains each upstream project's own OSS license. | Attribute CVEfixes. Filter to Java. Used for **SFT training pairs**. |
| **Juliet Test Suite (Java)** | Synthetic, labeled good/bad Java samples per CWE (NIST SARD). | **CC0 / public domain** (US Gov work). | Great for CWE coverage breadth; clearly synthetic. Used for **SFT training pairs**. |
| **Vul4J** | 79 PoV-reproducible real Java vulns, each with a human patch + a failing Proof-of-Vulnerability test, runnable via the `vul4j` CLI. | **CC-BY 4.0** (dataset/metadata). Each checked-out project keeps its own OSS license. | Used for the **executable eval** (fail-before / pass-after). Attribute Vul4J. |
| **VJBench / llm-vul** | 35 Vul4J + 15 new single-hunk Java vulns with compile/test states, plus **VJBench-trans** transformed variants (anti-memorization control). | Per the `lin-tan/llm-vul` repository license; transformed code derives from the upstream OSS projects under their respective licenses. | Used for the **executable eval** and the memorization control. Check the repo's `LICENSE` before redistribution. |

**Attribution.** When publishing results, cite CVEfixes, the NIST Juliet/SARD
suite, Vul4J, and VJBench/llm-vul. Underlying source files carry their original
upstream OSS licenses; this repo redistributes **none** of that code (data/ is
ignored) — you fetch it locally via the corpora above and the `vul4j` CLI.

---

## Two ways to invoke (one implementation)

The two entry points each have a **canonical module** under `data/prep/` and a
**thin top-level shim** in `data/`. Both names run the exact same code (single
source of truth — no logic is duplicated), so the console scripts and `-m`
invocations are interchangeable:

| Task | Canonical module | Top-level shim | Console script |
|------|------------------|----------------|----------------|
| Build SFT set | `python -m data.prep.prepare_sft` | `python -m data.prepare_sft` | `pp-prep` |
| Build eval manifest | `python -m data.prep.build_eval_set` | `python -m data.build_eval_set` | `pp-build-eval` |

The shims (`data/prepare_sft.py`, `data/build_eval_set.py`) just re-export and
delegate to `data.prep.*`; edit the pipeline only in `data/prep/`.

---

## How the pipeline uses the data

### 1. `prepare_sft.py` — build the SFT set (leakage-free)

```bash
python -m data.prep.prepare_sft \
  --raw data/raw/ \
  --out data/sft/train.jsonl \
  --eval-out data/sft/eval_heldout.jsonl \
  --split temporal \           # or: --cve-split
  [--cutoff-date 2022-01-01] \ # auto-derived if omitted
  --min-jaccard 0.9 \
  --seed 13
```

Contract:
1. **Load** raw `(vuln_code, fixed_code, cve, cwe, date, project)` records from
   `--raw` (`.json` list/object or `.jsonl`; common key aliases tolerated).
2. **Dedup** on the normalized `(vuln, fixed)` pair: exact SHA-1 of the
   structurally-normalized pair **plus** near-dup via token-Jaccard
   `>= --min-jaccard`; on collision keep the **earliest by date**.
3. **Split** so no CVE family (and, defensively, no project) leaks across the
   boundary — `temporal` (train = before cutoff, eval = on/after; undated → train)
   or `--cve-split` (whole families assigned deterministically by `--seed`). The
   run asserts no CVE overlap and aborts if leakage is detected.
4. **Strip leaks** from the instruction+input via `strip_leaky_tokens`
   (CWE/CVE/path/commit/marker/bug-id). The **output** (human patch) is kept
   verbatim — it is the learning target.
5. **Emit** instruction JSONL:
   `{"instruction": ..., "input": "<vuln file>", "output": "<patched file>", "meta": {...non-leaky...}}`
   to the train and held-out files. `meta` deliberately omits cve/cwe/source so
   the example stays leak-free even if `meta` is concatenated downstream.

### 2. `build_eval_set.py` — assemble the eval manifest

```bash
python -m data.prep.build_eval_set \
  --vul4j-ids data/raw/vul4j_ids.txt \
  [--vul4j-meta data/raw/vul4j_meta.json] \   # offline metadata cache
  --vjbench data/raw/vjbench/ \
  --out data/eval/manifest.jsonl \
  --cwe-focus config/cwe_focus.yaml \
  [--include-trans]                           # add VJBench-trans variants
```

Produces one `EvalManifestEntry` per line:
`{id, project, cwe, source, vulnerable_file, pov_tests, human_patch_ref, semgrep_covered, transformed}`.
No checkout happens here — the eval harness (`eval/run_eval.py`) does the
`vul4j checkout` and inflates each entry into a `harness.verdict.BugRecord`.
`semgrep_covered` is `True` iff the bug's CWE appears in `config/cwe_focus.yaml`
(the AND-gate's "covered" stratum). Vul4J metadata is resolved as:
cached `--vul4j-meta` → `vul4j info <id>` → minimal stub (the build never crashes
if the `vul4j` CLI is missing — it warns once and emits stubs).

---

## Shared contracts

The data-prep dataclasses (`SFTExample`, `EvalManifestEntry`) live in
`data/prep/schemas.py` and are **local** to data prep. The canonical gate
contracts (`BugRecord`, `Patch`, `LayerResult`, `GateVerdict`) are defined
**only** in `harness/verdict.py` and are never redefined here.
`EvalManifestEntry.source` uses the same `"vul4j"` / `"vjbench"` vocabulary as
`harness.verdict.SourceName` so the eval harness maps an entry onto a `BugRecord`
without translation; VJBench-trans variants keep `source="vjbench"` and set
`transformed=True`.

---

## Reproducibility & ignore rules

- Builds are deterministic for a fixed `--seed` (by-CVE split) and a fixed
  `--cutoff-date` (temporal split). Dedup ordering is stable.
- The root `.gitignore` excludes `data/`, `*.jsonl`, `models/`, secrets, and all
  confidential material. **Verify** with `git status` that no dataset file is
  staged before pushing (`scripts/push_to_github.sh`).

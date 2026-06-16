# PatchPilot — MERIT Run-book (the rigorous executable-proof eval)

The full, no-shortcuts eval: real Vul4J vulnerabilities → fixer patch → **compiles +
passes the original regression suite + the PoV exploit test flips fail→pass + Semgrep
(AND CodeQL on a subset) clean + AST non-deletion guard** → the **Functionality-
Preserved & Vuln-Cleared Rate**, base vs a **real leakage-free LoRA**.

**Honest odds (research-assessed):** a defensible **8–15 bug** executable-PoV eval,
base-vs-LoRA, is **~70–80% likely** if the corpus+LoRA are done first. Full CodeQL
across the subset is a coin-flip (→ stretch). All 79 bugs is **not** the 1.5-day bar.

**Golden rule:** do it in the order below — the early steps have **zero pod/Vul4J
dependency** and lock the merit before the risky build-flakiness step.

---

## Step 1 — Real leakage-free corpus FIRST (CPU/network, no GPU, no Vul4J)
Makes "fine-tuned beats base" an *honest* claim; depends on nothing fragile. The
builder + the 76-CVE/87-repo holdout (config/vul4j_dataset.csv, committed) are
VERIFIED working. **Run on the POD** — CVEfixes v1.0.8 is a 12.7 GB zip (fast there).
```bash
apt-get install -y unzip sqlite3
wget -O CVEfixes.zip "https://zenodo.org/records/13118970/files/CVEfixes_v1.0.8.zip?download=1"
unzip -o CVEfixes.zip
SQL=$(find . -name 'CVEfixes*.sql*' | head -1)             # the SQL dump inside
case "$SQL" in *.gz) gunzip -kf "$SQL"; SQL="${SQL%.gz}";; esac
sqlite3 CVEfixes.db < "$SQL"                                # build the SQLite DB (~minutes)
pip install datasketch
python -m data.prep.build_cvefixes_corpus --db CVEfixes.db \
    --out data/sft/train.jsonl --provenance data/sft/provenance.json \
    --vul4j-csv config/vul4j_dataset.csv --cutoff 2021-01-01   # holdout CSV already in repo
```
✅ Output: `data/sft/train.jsonl` + the **4-number provenance table**
(raw → after Vul4J holdout → after temporal cut → after dedup). *That table is the
merit.* Target ~1–3k clean pairs. If thin, top up with JavaVFC (Zenodo 13731781).
**Tip:** `git add -f data/sft/train.jsonl && git commit && git push` it (small) so it
survives the wipe and you can re-LoRA next session without rebuilding the 12.7 GB DB.

## Step 2 — Real LoRA on that corpus (~0.5–1.5 GPU-h)
Reuse the working pipeline + the SAME hyperparams (no tuning time lost):
```bash
python -m train.finetune_lora --config config/train_quick.yaml \
    --model Qwen/Qwen2.5-Coder-32B-Instruct --data data/sft/train.jsonl \
    --out models/fixer-lora-real
```
Now base-vs-LoRA is a real claim **regardless of how the Vul4J eval goes.**

## Step 3 — Vul4J env + ONE-bug end-to-end smoke (HIGH RISK — the day is won/lost here)
```bash
bash scripts/setup_vul4j.sh
source /root/vul4j/.venv/bin/activate && export PATH=/opt/apache-maven-3.3.9/bin:$PATH
vul4j status                       # Java 7/8/11/16 + Maven all GREEN
vul4j reproduce --id VUL4J-50      # PoV FAILS on vuln, PASSES on patch  (cleanest bug)
```
Then push that one bug through the FULL gate, base vs LoRA, and **time the build** to
calibrate the per-bug budget.
> **First 10 min:** confirm `harness.layers.vul4j_runner` shells to *this* `vul4j` CLI.
> If the native 4-JDK matrix fights → fall back to the `tuhhsoftsec/vul4j` Docker image
> on your **RTX-5070Ti laptop** (Docker guaranteed there); keep LoRA/serving on the pod.

## Step 4 — Scale the gate to the curated set, base vs LoRA (~2–3 h)
```bash
grep -oE 'VUL4J-[0-9]+' config/vul4j_eval_ids.txt > data/raw/vul4j_ids.txt
make build-eval
# serve base 32B as `fixer`, run; then serve LoRA as `fixer-ft`, run:
make eval MODEL_TAG=base       FIXER_MODEL=fixer
make eval MODEL_TAG=finetuned  FIXER_MODEL=fixer-ft
python -m eval.metrics --results results/eval_finetuned.json
```
**Pre-filter** with `vul4j reproduce` and compute the rate over **only the green set**.
*8 fully-verified PoV-flip bugs beat 15 half-broken ones — report N honestly.*

## Step 5 — CodeQL corroboration on 3–5 bugs (STRETCH, ~1–2 h)
```bash
bash scripts/setup_codeql.sh
# run on XXE/path-traversal/deser where CodeQL dataflow shines: VUL4J-47/64/65/41/78
# (commands printed by setup_codeql.sh; --build-mode none first, compile-trace fallback)
```
If dep resolution fights it → drop to 2 bugs or 0 and **say so** (never fake CodeQL numbers).

## Step 6 — Writeup
Provenance/dedup table + a **per-bug gate matrix** (compile / regression / PoV-flip /
Semgrep / CodeQL / AST — base vs LoRA) + the honest N. Clearly separate
**"functionally verified" (PoV+regression)** from **"statically cleared only."**

---

## Fallback ladder (merit-preserving)
1. CodeQL won't resolve deps → Semgrep + PoV-flip + regression + AST across all bugs; CodeQL deferred as environment-bound future work.
2. Native 4-JDK fights the pod → run Vul4J via Docker on the **laptop**; LoRA/serving on the pod.
3. Vul4J flaky across bugs → shrink to the 5–8 that reliably reproduce (commons-*/jsoup/javamelody); report N.
4. Vul4J blocked everywhere → PoV+regression on what works, Semgrep static-only on the rest, clearly separated.
5. GPU time exhausted → ship Step 1+2 (real corpus + provenance + real LoRA) + the **single-bug** end-to-end demo. Methodology proven on one real bug *with corpus rigor* is a defensible MVP.

## The unmitigable risk (honest)
The recipe's facts are verified live; the risk I can't test without the pod is **per-repo
Maven build flakiness** (2013–2021 projects pulling dead/relocated deps off Central) — expect
a minority of bugs to be unbuildable, which is exactly why the bar is a **curated green
subset (~12–15)**, not all 79. The 25 GB persistent home is too small for `~/.m2`, so do the
Vul4J eval in **one session** to keep the Maven cache warm.

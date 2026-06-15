# PatchPilot v2 — MI300X Run-Book (Mon Jun 15 → Wed Jun 17, 8:30 PM IST)

**Goal:** ship a *working* demo where ONE real Java vulnerability flips
**red → green** (exploit fails → passes, both scanners clear) — base model vs
fine-tuned — plus a live `rocm-smi` shot proving two 32B models co-resident on one
MI300X. Everything else is bonus.

**Golden rule:** protect the demo over breadth. If you must cut, cut the retry
loop and the DPO stretch — **never** cut the fail→pass flip or the rocm-smi proof.

**GPU budget:** ~12 GPU-hrs per 24h window, first-come-first-serve. The clock runs
only while a notebook is live — hit **Turn-off Session** when idle. Total plan
below uses **~6–8 GPU-hrs**, leaving margin for re-runs.

---

## ⚠️ STEP 0 (do this FIRST — it decides your architecture)

The verification gate needs **Vul4J** (Docker + JDK 7/8/11/16), **Semgrep**, and
**CodeQL**. The GPU work needs the **pod**. Where does the *gate* run?

On the pod, run:
```bash
pip install vul4j semgrep 2>&1 | tail -2
which java; java -version 2>&1 | head -1
docker info >/dev/null 2>&1 && echo "DOCKER OK on pod" || echo "NO docker on pod"
```

- **If `DOCKER OK on pod`** (or `vul4j reproduce --id VUL4J-10` works natively):
  → **Architecture A — everything on the pod.** Simplest. Skip to Phase 1.
- **If `NO docker on pod`:**
  → **Architecture B — split (recommended fallback):**
  - **Pod (MI300X):** serve models, fine-tune, *generate* patches → save to JSONL → download.
  - **Laptop (RTX 5070 Ti, Docker works):** run the **gate** (Vul4J + Semgrep + CodeQL)
    on the downloaded patches → produce the red→green verdicts + the demo.
  - Bridge = GitHub / file download (you already push from the pod).

> The CPU gate harness is identical on both; only *where* it runs changes. The
> laptop is the safe place for the gate because Docker is guaranteed there.

---

## Phase 1 — Bring up the repo (CPU, ~20 min, no GPU)

On the pod **and** the laptop:
```bash
git clone <your-private-repo-url> patchpilot-dualguard && cd patchpilot-dualguard
python -m pip install -e .                 # editable install
python -m pip install -r requirements-harness.txt
make test                                  # expect 18/18 passing
bash scripts/setup_semgrep.sh              # pin Semgrep + rules
bash scripts/setup_codeql.sh               # download pinned CodeQL bundle (laptop/where gate runs)
make smoke                                 # offline end-to-end: human-patch cleared + delete-the-sink rejected
```
✅ Checkpoint: `make test` green, `make smoke` prints the AST guard accepting the
human patch and rejecting delete-the-sink. (This already works today.)

---

## Phase 2 — First GPU session: PROVE THE AMD STORY (>80 GB config FIRST, ~2–3 GPU-hrs)

**This session's deliverable is the marquee AMD artifact:** a live `rocm-smi` showing
**>80 GB of model on one MI300X** — something an 80 GB H100/A100 physically cannot do.
The verification gates run on CPU (correct — you don't burn a GPU on a linter); the
GPU's job is the *intelligence at scale*. Make that visible FIRST, not as an afterthought.

**2a. Validate + 7B smoke + START the big download (downloads are the long pole):**
```bash
bash scripts/setup_cloud.sh                # pip installs (vllm/peft/trl) + hf + git
amd-smi || rocm-smi                         # confirm 1× MI300X, 192 GB
# quick smoke that vLLM works on ROCm AT ALL:
vllm serve Qwen/Qwen2.5-Coder-7B-Instruct --served-model-name fixer --port 8000 \
  --max-model-len 8192 --gpu-memory-utilization 0.4 &
curl -s localhost:8000/v1/models | python -m json.tool   # JSON => ROCm/vLLM works
# pull the BIG models for the load-bearing config (slow — start EARLY):
huggingface-cli download Qwen/Qwen2.5-Coder-32B-Instruct
huggingface-cli download Qwen/Qwen2.5-32B-Instruct        # the judge (or -72B- for a bigger number)
pkill -f "vllm serve"                       # stop the 7B smoke before bringing up the big config
```

**2b. Bring up the LOAD-BEARING config — fixer + judge co-resident on ONE card:**
```bash
# serve/launch_vllm.sh dual = fixer(:8000) + judge(:8001), split --gpu-memory-utilization
bash serve/launch_vllm.sh dual Qwen/Qwen2.5-Coder-32B-Instruct Qwen/Qwen2.5-32B-Instruct
# in a 2nd terminal — THE MONEY SHOT (screen-record it):
bash scripts/rocm_smi_watch.sh             # expect >80 GB (≈128–144 GB) used on ONE MI300X
```
✅ **Checkpoint (the AMD win):** `rocm-smi` shows two 32B-class models co-resident at
**>80 GB on a single MI300X**. Capture the clip + a still NOW. Deck line:
*"The fixer and its own judge live on one AMD card — impossible below 192 GB. Show me
an 80 GB GPU doing this."*

**2c. Fallback ladder — ALWAYS cross 80 GB (take the highest rung that's stable):**
1. co-resident **32B fixer + 72B judge** (~144 GB) — best number.
2. **70B fixer alone** (~140 GB) — "doesn't fit on 80 GB, period."
3. co-resident **2× 32B** (~128 GB).
4. floor: **32B + big batch / long-context** to push the KV cache past 80 GB.
   A 7B alone (~30 GB) does NOT answer "use the card" — never ship that as the headline.

**2d. THEN one bug red→green** using the big served fixer (the golden path):
```bash
printf "VUL4J-10\nVUL4J-12\nVUL4J-43\n" > data/raw/vul4j_ids.txt   # well-covered CWEs
make build-eval                                                     # data/eval/manifest.jsonl
make eval EVAL_SET=data/eval/manifest.jsonl MODEL_TAG=base \
     FIXER_URL=http://localhost:8000/v1 FIXER_MODEL=fixer N_RETRIES=0
# find a bug the base model FAILS -> that's your demo case.
```
✅ Checkpoint: the gate produces a verdict end-to-end on **real Vul4J** (compile +
regression + PoV + Semgrep + CodeQL + AST), driven by the big model on the MI300X.

> Architecture B (gate on laptop): run `make eval` on the laptop after downloading the
> pod's generated patches; keep the manifest + Vul4J checkouts on the laptop.
> Bonus: the SAME served model also powers WebGate — `python -m harness.webgate
> --original webgate/demo/broken.html --fixer-url http://localhost:8000/v1 --fixer-model fixer`.

---

## Phase 3 — Fine-tune the fixer LoRA (~1–1.5 GPU-hrs)

```bash
# 3a. Build leakage-free SFT data from public corpora (CVEfixes/JavaVFC, deduped, temporal split)
make prep                                  # -> data/sft/train.jsonl + eval_heldout.jsonl
# 3b. LoRA SFT (BF16, ~2 epochs). Start 7B; 32B if budget allows.
make train TRAIN_CONFIG=config/train.yaml  # saves adapter to models/fixer-lora
# 3c. serve the fine-tuned adapter
vllm serve Qwen/Qwen2.5-Coder-7B-Instruct --enable-lora \
  --lora-modules fixer-ft=models/fixer-lora \
  --served-model-name fixer-ft --port 8000 --max-model-len 16384 &
```
✅ Checkpoint: adapter trained (note wall-clock + adapter size for Slide 4).

---

## Phase 4 — The money number: fine-tuned vs FAIR baseline (~1–2 GPU-hrs)

```bash
# identical bugs, identical retries, identical gate — only the model differs.
make eval     MODEL_TAG=finetuned FIXER_MODEL=fixer-ft   # results/eval_finetuned.json
make baseline                                            # fair few-shot+retry baseline
python -m eval.metrics --results results/eval_finetuned.json   # stratified table + Wilson CI
```
✅ Checkpoint: a **Functionality-Preserved & Vuln-Cleared Rate** with n + 95% CI,
split by source and Semgrep-covered. Report a sober honest number (35–50% is a WIN
with this gate). Save both JSONs.

> The AMD WOW (>80 GB co-resident fixer+judge) was captured in **Phase 2** — reuse
> that still/clip here on Slide 4. If you couldn't bring up the big config Mon,
> retry a fallback-ladder rung now; the rate is the story, the rocm-smi shot is the
> sponsor proof — you want both.

---

## Phase 5 — Demo + dashboard + deck + submit (CPU, Wed)

```bash
make ui RESULTS=results/eval_finetuned.json   # Streamlit: 5 badges + fail→pass line + rocm-smi tile
```
- **Record the canonical run** (temperature=0, fixed seed) on the chosen demo bug:
  base patch → red badges; fine-tuned patch → green badges + exploit flips fail→pass.
  Rehearse ≥5×; keep the recording as the submission artifact (don't risk live).
- **5 slides** (handbook structure): ① title/team ② problem + stakes hook
  ③ architecture + the DualGuard gate ④ **Performance/Scale/Time** (model, LoRA
  wall-clock/epochs/adapter size, throughput tok/s, rocm-smi GB, the rate table)
  ⑤ summary + the red→green screenshot + repo/demo links.
- **Submit** via Ultimatix → Prime Events: deck (PDF) + demo video + code
  (GitHub link or `git archive -o patchpilot.zip HEAD`). **Buffer: submit by Wed 6 PM**, not 8:29.

---

## Time-box (target ~6–8 GPU-hrs of your 12/24h)

| When | Focus | GPU |
|---|---|---|
| **Mon AM** | Step 0 decision + Phase 1 (repo green on pod & laptop) | 0 |
| **Mon PM** | Phase 2: bring up the **>80 GB co-resident config + capture rocm-smi** (the AMD win) + one bug red→green | ~2–3h |
| **Tue AM** | Phase 3: prep data + LoRA train (on the big model if budget allows) | ~1.5h |
| **Tue PM** | Phase 4: finetuned vs baseline eval → the number (co-residency already captured Mon) | ~3h |
| **Wed AM** | Phase 5: dashboard + record demo + build slides | ~1h |
| **Wed PM** | Final eval re-run if needed + **submit by 6 PM** | ~1h |

## Fallback ladder (if you're behind)
1. Drop 32B → keep **7B** fixer (still fine-tunes, still flips red→green). The rate is the story, not the model size.
2. Drop the live co-residency → use the **pre-recorded** rocm-smi proof.
3. Drop DPO + retry loop entirely (they were always stretch).
4. Worst case: demo the gate on a **base-vs-human** patch (red→green still lands) and frame fine-tuning as "in progress" — you still have a working, verifiable, AMD-backed solution.

## Don't-trip-on-these
- Storage is wiped — `git push` (or `git archive`) your code **and** download `models/fixer-lora` + `results/*.json` after every session.
- Re-run `setup_cloud.sh` + restart vLLM after any pod relaunch (deps/processes don't persist).
- Use only **public** datasets. Keep TCS-confidential docs out of the repo.
- Pin temperature=0 + seed for the demo so the red→green flip is reproducible on stage.

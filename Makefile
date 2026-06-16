# PatchPilot v2 "DualGuard" — developer entrypoints.
# CPU/JVM verification harness targets run anywhere; cloud targets run only on
# the AMD MI300X notebook. `make help` lists everything.
#
# Override the interpreter with e.g.  make test PY=python3
PY ?= python
PIP ?= $(PY) -m pip
PYTEST ?= $(PY) -m pytest

# Default knobs (override on the command line: make eval MODEL_TAG=baseline)
EVAL_SET   ?= data/eval/manifest.jsonl
MODEL_TAG  ?= finetuned
FIXER_URL  ?= http://localhost:8000/v1
FIXER_MODEL ?= fixer
JUDGE_URL  ?= http://localhost:8001/v1
JUDGE_MODEL ?= judge
N_RETRIES  ?= 1
RESULTS    ?= results/eval_$(MODEL_TAG).json
GATE_CONFIG ?= config/gate.yaml
EVAL_CONFIG ?= config/eval.yaml
TRAIN_CONFIG ?= config/train.yaml
SERVE_CONFIG ?= config/serve.yaml

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ─────────────────────────── Setup (CPU harness) ───────────────────────────
.PHONY: install
install: ## Install the CPU/JVM harness dependencies
	$(PIP) install -r requirements-harness.txt

.PHONY: install-dev
install-dev: install ## Install harness deps + the package in editable mode
	$(PIP) install -e .

.PHONY: setup-sast
setup-sast: ## Install/pin Semgrep + download the pinned CodeQL bundle
	bash scripts/setup_semgrep.sh
	bash scripts/setup_codeql.sh

# ─────────────────────────── Setup (cloud GPU) ─────────────────────────────
.PHONY: install-cloud
install-cloud: ## Install GPU-only deps (vllm/peft/trl) on the MI300X notebook
	$(PIP) install -r requirements-cloud.txt

# ─────────────────────────── Quality gates ────────────────────────────────
.PHONY: test
test: ## Run the unit-test suite (verdict truth table, metric, AST, SAST parse)
	$(PYTEST) -q tests

.PHONY: smoke
smoke: ## End-to-end CPU smoke test on one bug (human patch -> cleared=True)
	bash scripts/run_smoke.sh

# ───────────────────────── Gate / data / eval ─────────────────────────────
.PHONY: gate
gate: ## Run the 5-layer gate on one bug+patch (BUG=bug.json PATCH=patch.json)
	$(PY) -m harness.gate --bug-json $(BUG) --patch-json $(PATCH) \
		--config $(GATE_CONFIG) -o verdict.json

.PHONY: prep
prep: ## Build the leakage-free SFT train/held-out JSONL from data/raw
	$(PY) -m data.prep.prepare_sft --raw data/raw/ \
		--out data/sft/train.jsonl --eval-out data/sft/eval_heldout.jsonl \
		--split temporal --min-jaccard 0.9 --seed 13

.PHONY: build-eval
build-eval: ## Assemble the Vul4J/VJBench eval manifest
	$(PY) -m data.prep.build_eval_set --vul4j-ids data/raw/vul4j_ids.txt \
		--vjbench data/raw/vjbench/ --out $(EVAL_SET) \
		--cwe-focus config/cwe_focus.yaml

.PHONY: eval
eval: ## Generate + gate patches over the eval set, write strata results
	$(PY) -m eval.run_eval --eval-set $(EVAL_SET) --model-tag $(MODEL_TAG) \
		--fixer-url $(FIXER_URL) --fixer-model $(FIXER_MODEL) \
		--judge-url $(JUDGE_URL) --judge-model $(JUDGE_MODEL) \
		--n-retries $(N_RETRIES) --config $(EVAL_CONFIG) -o $(RESULTS)

.PHONY: baseline
baseline: ## Run the fair few-shot+retry baseline (identical bugs/gate)
	$(PY) -m eval.baselines --eval-set $(EVAL_SET) \
		--fixer-url $(FIXER_URL) --fixer-model baseline \
		--judge-url $(JUDGE_URL) --judge-model $(JUDGE_MODEL) \
		--n-retries $(N_RETRIES) -o results/eval_baseline.json

# ─────────────────────────── Train / serve (cloud) ────────────────────────
.PHONY: quick-eval
quick-eval: ## FAST proof: Semgrep red->green on held-out vulnerable Java (no Vul4J)
	$(PY) -m eval.build_samples && $(PY) -m eval.quick_eval --fixer-url $(FIXER_URL) --fixer-model $(FIXER_MODEL) --model-tag $(MODEL_TAG) -o results/quick_$(MODEL_TAG).json

.PHONY: train
train: ## LoRA SFT on the MI300X (reads config/train.yaml)
	$(PY) -m train.finetune_lora --config $(TRAIN_CONFIG)

.PHONY: train-quick
train-quick: ## Guaranteed bootstrap LoRA on the tracked seed set (proves the pipeline tonight)
	$(PY) -m train.build_seed_sft
	$(PY) -m train.finetune_lora --config config/train_quick.yaml

.PHONY: serve
serve: ## Print the exact co-resident vLLM fixer+judge launch commands
	$(PY) -m serving.launch_vllm --config $(SERVE_CONFIG) --print

.PHONY: serve-up
serve-up: ## Spawn the co-resident vLLM fixer+judge servers on the MI300X
	$(PY) -m serving.launch_vllm --config $(SERVE_CONFIG)

# ─────────────────────────── UI / proof ───────────────────────────────────
.PHONY: ui
ui: ## Launch the Streamlit dashboard against a results file
	streamlit run ui/dashboard.py -- --results $(RESULTS)

.PHONY: rocm-watch
rocm-watch: ## Live single-card co-residency proof (rocm-smi loop)
	bash scripts/rocm_smi_watch.sh

# ─────────────────────────── Repo plumbing ────────────────────────────────
.PHONY: push
push: ## Commit + push to GitHub from the AMD notebook (needs GITHUB_TOKEN/REPO)
	bash scripts/push_to_github.sh "DualGuard snapshot"

.PHONY: clean
clean: ## Remove caches and local build artifacts (keeps data/ & models/)
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -f verdict.json

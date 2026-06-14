"""MG7 · STRETCH: DPO on the dual-oracle + executable-test signal.

STATUS: STRETCH GOAL — ship the LoRA SFT fixer + the verification gate FIRST.
This module closes the loop in TRAINING (not just eval): it mines preference pairs
where a *gate-cleared* patch (chosen) beats a *gate-failed* patch (rejected) for the
same bug, then runs DPO so the fixer learns to produce verifiable, behavior-
preserving fixes. This is the genuinely novel "train the loop, not just evaluate it"
contribution — do it only if SFT + gate + demo are already solid.

Heavy deps imported lazily; byte-compiles and ``--help`` works without a GPU.

CLI::

    # 1) mine preference pairs by sampling the fixer and gating each candidate
    python -m train.dpo_stub build-pairs --eval-set data/eval/manifest.jsonl \\
        --fixer-url http://localhost:8000/v1 --fixer-model fixer \\
        --samples 4 --out data/dpo/pairs.jsonl
    # 2) DPO-train on the mined pairs
    python -m train.dpo_stub train --pairs data/dpo/pairs.jsonl \\
        --model Qwen/Qwen2.5-Coder-7B-Instruct --out models/fixer-dpo
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional


@dataclass
class PreferencePair:
    """A DPO preference triple for one bug."""

    bug_id: str
    prompt: str
    chosen: str
    rejected: str

    def to_jsonl(self) -> str:
        return json.dumps(asdict(self))


def mine_pairs_for_bug(
    bug,
    gate_mod: Any,
    cfg: Any,
    fixer_url: str,
    fixer_model: str,
    samples: int,
    temperature: float,
) -> List[PreferencePair]:
    """Sample `samples` candidate patches, gate each, and pair cleared vs failed."""
    from eval import fixer_client
    from eval.fixer_client import read_original_code

    prompt_src = read_original_code(bug)
    cleared: List[str] = []
    failed: List[str] = []
    for k in range(max(1, samples)):
        try:
            patch = fixer_client.generate_patch(
                bug=bug,
                attempt=k,
                base_url=fixer_url,
                model=fixer_model,
                temperature=temperature,
            )
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"[dpo] sample {k} for {bug.id} failed: {exc}\n")
            continue
        verdict = gate_mod.run_gate(bug, patch, cfg)
        (cleared if verdict.cleared else failed).append(patch.patched_code)

    pairs: List[PreferencePair] = []
    for c in cleared:
        for r in failed:
            pairs.append(
                PreferencePair(bug_id=bug.id, prompt=prompt_src, chosen=c, rejected=r)
            )
    return pairs


def build_pairs(argv_ns: argparse.Namespace) -> int:
    """Mine DPO preference pairs across the eval set and write JSONL."""
    from eval.run_eval import _bug_from_entry, load_manifest
    from harness import gate as gate_mod
    from harness.layers import vul4j_runner

    cfg = gate_mod.GateConfig.from_yaml("config/gate.yaml")
    entries = load_manifest(argv_ns.eval_set)
    os.makedirs(os.path.dirname(argv_ns.out) or ".", exist_ok=True)
    os.makedirs(argv_ns.checkout_root, exist_ok=True)

    total = 0
    with open(argv_ns.out, "w", encoding="utf-8") as fh:
        for entry in entries:
            bug_id = str(entry.get("id"))
            dest = os.path.join(argv_ns.checkout_root, bug_id)
            try:
                if not os.path.isdir(dest) or not os.listdir(dest):
                    vul4j_runner.checkout(bug_id, dest)
            except Exception as exc:  # noqa: BLE001
                sys.stderr.write(f"[dpo] checkout {bug_id} failed: {exc}\n")
                continue
            bug = _bug_from_entry(entry, dest)
            pairs = mine_pairs_for_bug(
                bug, gate_mod, cfg,
                argv_ns.fixer_url, argv_ns.fixer_model,
                argv_ns.samples, argv_ns.temperature,
            )
            for p in pairs:
                fh.write(p.to_jsonl() + "\n")
                total += 1
            print(f"[dpo] {bug_id}: mined {len(pairs)} pair(s)")
    print(f"[dpo] wrote {total} preference pairs -> {argv_ns.out}")
    return 0


def train_dpo(argv_ns: argparse.Namespace) -> int:
    """Run DPO on mined preference pairs (cloud/MI300X)."""
    try:
        import torch
        from datasets import load_dataset
        from peft import LoraConfig
        from transformers import AutoModelForCausalLM, AutoTokenizer
        from trl import DPOConfig, DPOTrainer
    except ImportError as exc:  # pragma: no cover - cloud-only
        raise SystemExit(
            f"[dpo] missing GPU deps: {exc}. Run pip install -r requirements-cloud.txt"
        )

    if not os.path.isfile(argv_ns.pairs):
        raise SystemExit(f"[dpo] pairs file not found: {argv_ns.pairs} (run build-pairs).")

    tokenizer = AutoTokenizer.from_pretrained(argv_ns.model, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        argv_ns.model, torch_dtype=torch.bfloat16,
        trust_remote_code=True, device_map="auto",
    )
    dataset = load_dataset("json", data_files=argv_ns.pairs, split="train")

    peft_config = LoraConfig(
        r=16, lora_alpha=32, lora_dropout=0.05,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
        bias="none", task_type="CAUSAL_LM",
    )
    dpo_config = DPOConfig(
        output_dir=argv_ns.out,
        num_train_epochs=argv_ns.epochs,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=16,
        learning_rate=5e-6,
        bf16=True,
        beta=0.1,
        logging_steps=5,
        report_to="none",
    )
    trainer = DPOTrainer(
        model=model, args=dpo_config,
        train_dataset=dataset, processing_class=tokenizer,
        peft_config=peft_config,
    )
    trainer.train()
    trainer.save_model(argv_ns.out)
    print(f"[dpo] saved DPO adapter -> {argv_ns.out}")
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m train.dpo_stub",
        description="STRETCH: DPO on the dual-oracle + executable-test signal.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    bp = sub.add_parser("build-pairs", help="Mine preference pairs via sample+gate.")
    bp.add_argument("--eval-set", required=True)
    bp.add_argument("--fixer-url", required=True)
    bp.add_argument("--fixer-model", default="fixer")
    bp.add_argument("--samples", type=int, default=4)
    bp.add_argument("--temperature", type=float, default=0.8)
    bp.add_argument("--checkout-root", default="data/checkouts")
    bp.add_argument("--out", default="data/dpo/pairs.jsonl")

    tp = sub.add_parser("train", help="DPO-train on mined pairs.")
    tp.add_argument("--pairs", default="data/dpo/pairs.jsonl")
    tp.add_argument("--model", default="Qwen/Qwen2.5-Coder-7B-Instruct")
    tp.add_argument("--out", default="models/fixer-dpo")
    tp.add_argument("--epochs", type=float, default=1.0)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if args.cmd == "build-pairs":
        return build_pairs(args)
    if args.cmd == "train":
        return train_dpo(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["PreferencePair", "mine_pairs_for_bug", "build_pairs", "train_dpo", "main"]

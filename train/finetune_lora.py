"""MG7 · BF16 LoRA SFT of the Qwen2.5-Coder fixer on the MI300X (PEFT/TRL).

Fine-tunes a code LLM on instruction-formatted (vulnerable -> fixed) Java pairs
produced by ``data/prep/prepare_sft.py``. BF16 + LoRA on a single AMD Instinct
MI300X via ROCm; no quantization needed (192 GB HBM).

All heavy deps (torch/transformers/peft/trl/datasets) are imported lazily so this
module byte-compiles and ``--help`` works without them.

CLI::

    python -m train.finetune_lora --config config/train.yaml
    python -m train.finetune_lora --model Qwen/Qwen2.5-Coder-7B-Instruct \\
        --data data/sft/train.jsonl --out models/fixer-lora --epochs 2 --lora-r 16
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
@dataclass
class TrainConfig:
    """LoRA SFT hyperparameters (mirrors config/train.yaml)."""

    model: str = "Qwen/Qwen2.5-Coder-7B-Instruct"
    data: str = "data/sft/train.jsonl"
    eval_data: Optional[str] = None
    out: str = "models/fixer-lora"
    epochs: float = 2.0
    lr: float = 2e-4
    batch_size: int = 1
    grad_accum: int = 16
    max_seq_len: int = 4096
    lora_r: int = 16
    lora_alpha: int = 32
    lora_dropout: float = 0.05
    lora_targets: List[str] = field(
        default_factory=lambda: [
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ]
    )
    warmup_ratio: float = 0.03
    seed: int = 13
    logging_steps: int = 5
    save_steps: int = 200

    @classmethod
    def from_yaml(cls, path: str) -> "TrainConfig":
        if not path or not os.path.isfile(path):
            return cls()
        try:
            import yaml  # type: ignore
        except ImportError:
            sys.stderr.write("[train] pyyaml missing; using default TrainConfig.\n")
            return cls()
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in raw.items() if k in known})


FIXER_TRAIN_SYSTEM = (
    "You are a secure-code remediation assistant. Given a Java file containing a "
    "known vulnerability (with its CWE), return the COMPLETE corrected file. Fix "
    "ONLY the vulnerability; preserve all other behavior. Output only the fixed "
    "Java file in a single ```java code block."
)


def _require_training_stack():
    """Import the GPU training stack, with a clear message if missing."""
    try:
        import torch  # noqa: F401
        import transformers  # noqa: F401
        import datasets  # noqa: F401
        import peft  # noqa: F401
        import trl  # noqa: F401
    except ImportError as exc:  # pragma: no cover - cloud-only
        raise SystemExit(
            "[train] missing GPU training deps: "
            f"{exc}. On the MI300X notebook run: pip install -r requirements-cloud.txt"
        )


def describe_accelerator() -> str:
    """Return a short ROCm/CUDA accelerator description (best effort)."""
    try:
        import torch

        if torch.cuda.is_available():
            name = torch.cuda.get_device_name(0)
            hip = getattr(torch.version, "hip", None)
            backend = f"ROCm/HIP {hip}" if hip else "CUDA"
            return f"{backend} · {name}"
        return "CPU only (no accelerator visible)"
    except Exception:  # noqa: BLE001
        return "torch not importable"


def build_chat_messages(example: Dict[str, Any]) -> List[Dict[str, str]]:
    """Build chat messages from an SFT example.

    Accepts either {"messages": [...]} (already chat-formatted) or
    {"prompt"/"instruction"/"input", "completion"/"output"/"fixed"} pairs.
    """
    if isinstance(example.get("messages"), list):
        return example["messages"]
    user = (
        example.get("prompt")
        or example.get("instruction")
        or example.get("input")
        or example.get("vulnerable")
        or ""
    )
    assistant = (
        example.get("completion")
        or example.get("output")
        or example.get("response")
        or example.get("fixed")
        or ""
    )
    return [
        {"role": "system", "content": FIXER_TRAIN_SYSTEM},
        {"role": "user", "content": str(user)},
        {"role": "assistant", "content": str(assistant)},
    ]


def make_formatting_func(tokenizer):
    """Return a TRL formatting function that renders the chat template."""

    def _fmt(example: Dict[str, Any]) -> str:
        messages = build_chat_messages(example)
        return tokenizer.apply_chat_template(messages, tokenize=False)

    return _fmt


def load_sft_dataset(path: str):
    """Load a JSONL SFT dataset via the `datasets` library."""
    from datasets import load_dataset

    if not os.path.isfile(path):
        raise SystemExit(f"[train] SFT data not found: {path} (run `make prep`).")
    return load_dataset("json", data_files=path, split="train")


def _print_plan(cfg: TrainConfig) -> None:
    print("[train] PatchPilot v2 — LoRA SFT plan")
    print(f"  accelerator : {describe_accelerator()}")
    print(f"  model       : {cfg.model}")
    print(f"  data        : {cfg.data}")
    print(f"  out         : {cfg.out}")
    print(f"  epochs      : {cfg.epochs}  lr={cfg.lr}  bsz={cfg.batch_size}x{cfg.grad_accum}")
    print(f"  lora        : r={cfg.lora_r} alpha={cfg.lora_alpha} drop={cfg.lora_dropout}")
    print(f"  max_seq_len : {cfg.max_seq_len}  seed={cfg.seed}")


def train(cfg: TrainConfig) -> int:
    """Run LoRA SFT. Returns a process exit code."""
    _require_training_stack()
    import torch
    from peft import LoraConfig
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from trl import SFTConfig, SFTTrainer

    _print_plan(cfg)

    tokenizer = AutoTokenizer.from_pretrained(cfg.model, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        cfg.model,
        torch_dtype=torch.bfloat16,
        trust_remote_code=True,
        device_map="auto",
    )

    peft_config = LoraConfig(
        r=cfg.lora_r,
        lora_alpha=cfg.lora_alpha,
        lora_dropout=cfg.lora_dropout,
        target_modules=cfg.lora_targets,
        bias="none",
        task_type="CAUSAL_LM",
    )

    # Convert to a conversational "messages" dataset; modern TRL auto-applies the
    # chat template (no formatting_func needed).
    def _to_messages(ex):
        return {"messages": build_chat_messages(ex)}

    train_ds = load_sft_dataset(cfg.data)
    train_ds = train_ds.map(_to_messages, remove_columns=train_ds.column_names)
    eval_ds = None
    if cfg.eval_data:
        eval_ds = load_sft_dataset(cfg.eval_data)
        eval_ds = eval_ds.map(_to_messages, remove_columns=eval_ds.column_names)

    # TRL renamed/removed several kwargs across versions (e.g. max_seq_length ->
    # max_length on SFTConfig; tokenizer -> processing_class on SFTTrainer). Build
    # the args tolerantly so this runs on both older (0.12+) and newer (1.x) TRL.
    import inspect

    sft_kwargs = dict(
        output_dir=cfg.out,
        num_train_epochs=cfg.epochs,
        per_device_train_batch_size=cfg.batch_size,
        gradient_accumulation_steps=cfg.grad_accum,
        learning_rate=cfg.lr,
        warmup_ratio=cfg.warmup_ratio,
        bf16=True,
        logging_steps=cfg.logging_steps,
        save_steps=cfg.save_steps,
        seed=cfg.seed,
        report_to="none",
    )
    _sft_params = inspect.signature(SFTConfig.__init__).parameters
    if "max_length" in _sft_params:
        sft_kwargs["max_length"] = cfg.max_seq_len
    elif "max_seq_length" in _sft_params:
        sft_kwargs["max_seq_length"] = cfg.max_seq_len
    sft_config = SFTConfig(**sft_kwargs)

    trainer_kwargs = dict(
        model=model,
        args=sft_config,
        train_dataset=train_ds,
        peft_config=peft_config,
    )
    if eval_ds is not None:
        trainer_kwargs["eval_dataset"] = eval_ds
    _trainer_params = inspect.signature(SFTTrainer.__init__).parameters
    if "processing_class" in _trainer_params:
        trainer_kwargs["processing_class"] = tokenizer
    elif "tokenizer" in _trainer_params:
        trainer_kwargs["tokenizer"] = tokenizer
    elif "formatting_func" in _trainer_params:
        trainer_kwargs["formatting_func"] = make_formatting_func(tokenizer)
    trainer = SFTTrainer(**trainer_kwargs)

    trainer.train()
    trainer.save_model(cfg.out)
    tokenizer.save_pretrained(cfg.out)
    print(f"[train] saved LoRA adapter to {cfg.out}")

    meta = {
        "base_model": cfg.model,
        "epochs": cfg.epochs,
        "lora_r": cfg.lora_r,
        "data": cfg.data,
    }
    with open(os.path.join(cfg.out, "patchpilot_train_meta.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m train.finetune_lora",
        description="BF16 LoRA SFT of the Qwen2.5-Coder fixer on the MI300X.",
    )
    p.add_argument("--config", default=None, help="Path to config/train.yaml.")
    p.add_argument("--model", default=None, help="Base model id (overrides config).")
    p.add_argument("--data", default=None, help="SFT JSONL (overrides config).")
    p.add_argument("--eval-data", default=None, help="Optional eval JSONL.")
    p.add_argument("--out", default=None, help="Adapter output dir (overrides config).")
    p.add_argument("--epochs", type=float, default=None)
    p.add_argument("--lora-r", type=int, default=None)
    p.add_argument("--dry-run", action="store_true", help="Print the plan and exit.")
    return p


def resolve_config(args: argparse.Namespace) -> TrainConfig:
    cfg = TrainConfig.from_yaml(args.config) if args.config else TrainConfig()
    if args.model:
        cfg.model = args.model
    if args.data:
        cfg.data = args.data
    if args.eval_data:
        cfg.eval_data = args.eval_data
    if args.out:
        cfg.out = args.out
    if args.epochs is not None:
        cfg.epochs = args.epochs
    if args.lora_r is not None:
        cfg.lora_r = args.lora_r
    return cfg


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    cfg = resolve_config(args)
    if args.dry_run:
        _print_plan(cfg)
        return 0
    return train(cfg)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "TrainConfig",
    "FIXER_TRAIN_SYSTEM",
    "build_chat_messages",
    "make_formatting_func",
    "load_sft_dataset",
    "describe_accelerator",
    "train",
    "main",
]

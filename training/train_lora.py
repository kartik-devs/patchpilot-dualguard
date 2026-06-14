"""Spec entry point ``python -m training.train_lora`` (MG7).

The full BF16 LoRA SFT implementation was authored as :mod:`train.finetune_lora`
(TrainConfig + Qwen chat-template formatting + TRL SFTTrainer, ROCm-aware). The
architect spec names this entry point ``training/train_lora.py``; this module is
a THIN, fully-runnable shim that delegates to the canonical implementation so the
two import paths are interchangeable with no duplicated logic:

    python -m training.train_lora --config config/train.yaml   # via this shim
    python -m train.finetune_lora --config config/train.yaml   # canonical module

The instruction->chat-template formatting the spec attributes to
``training/data_collator.py`` is available both there (:mod:`training.data_collator`)
and inside the canonical implementation; this shim re-exports the canonical
public surface (``main``, ``build_arg_parser``, ``resolve_config``,
``TrainConfig``) so the ``make train`` target and any direct imports work.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional

try:
    from train import finetune_lora as _impl
except Exception:  # pragma: no cover - direct-run fallback
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from train import finetune_lora as _impl

TrainConfig = _impl.TrainConfig
build_arg_parser = _impl.build_arg_parser
resolve_config = _impl.resolve_config

__all__ = ["TrainConfig", "build_arg_parser", "resolve_config", "main"]


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. Delegates verbatim to ``train.finetune_lora.main``."""
    return _impl.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())

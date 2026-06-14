"""DualGuard training package (cloud / MI300X only).

Modules:
* :mod:`train.finetune_lora` — BF16 LoRA SFT of the Qwen2.5-Coder fixer (PEFT/TRL).
* :mod:`train.dpo_stub`     — STRETCH: DPO on the dual-oracle + executable-test signal.

All heavy GPU deps (torch / transformers / peft / trl / datasets) are imported
lazily inside functions so the modules byte-compile and ``--help`` works on a CPU
box with none of them installed.
"""

__all__ = ["finetune_lora", "dpo_stub"]

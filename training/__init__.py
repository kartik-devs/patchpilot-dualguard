"""PatchPilot v2 \"DualGuard\" training package (MG7).

Contains the spec entry points :mod:`training.train_lora` (PEFT/TRL BF16 LoRA
SFT) and :mod:`training.data_collator` (instruction -> Qwen chat-template
collator). Heavy GPU deps (torch/transformers/peft/trl) are imported lazily
inside ``main()`` so the CPU-only harness stays importable.
"""

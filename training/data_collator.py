"""Instruction -> Qwen-chat-template tokenized collator (MG7).

Turns a :class:`data.prep.schemas.SFTExample` (or any object/dict with
``instruction`` / ``input`` / ``output``) into the Qwen ``<|im_start|>`` chat
format and tokenizes it for TRL's ``SFTTrainer``. Importing this module pulls in
NO heavy deps; a tokenizer is only required when the functions are actually
called.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional


FIXER_TRAIN_SYSTEM = (
    "You are a senior Java security engineer. Repair the single vulnerable Java file "
    "and return the COMPLETE patched file in one fenced ```java block. Preserve all "
    "behavior; fix only the vulnerability; never delete the vulnerable logic."
)


def _field(ex: Any, name: str, default: str = "") -> str:
    """Read ``name`` from a dataclass-like object or a dict, defaulting to ``default``."""
    if isinstance(ex, dict):
        return str(ex.get(name, default) or default)
    return str(getattr(ex, name, default) or default)


def build_chat_messages(ex: Any) -> List[Dict[str, str]]:
    """Build the system/user/assistant message list for one example.

    The user turn wraps the vulnerable file in a fenced ``java`` block; the
    assistant turn is the gold patched file (also fenced). The instruction text
    from the example (if any) is preferred over the default system prompt body.
    """
    instruction = _field(ex, "instruction", FIXER_TRAIN_SYSTEM)
    vulnerable = _field(ex, "input")
    patched = _field(ex, "output")
    user = (
        instruction.strip()
        + "\n\nVulnerable file:\n\n```java\n"
        + vulnerable
        + "\n```"
    )
    assistant = "```java\n" + patched + "\n```"
    return [
        {"role": "system", "content": FIXER_TRAIN_SYSTEM},
        {"role": "user", "content": user},
        {"role": "assistant", "content": assistant},
    ]


def format_example(ex: Any, tokenizer: Any) -> Dict[str, Any]:
    """Apply the Qwen chat template to one example and return tokenized tensors.

    Uses ``tokenizer.apply_chat_template`` (the supported Qwen path). Falls back
    to a manual ``<|im_start|>...<|im_end|>`` rendering if the tokenizer lacks a
    chat template, so this never silently produces an unlabeled blob.

    Args:
        ex: An SFTExample-like object/dict with instruction/input/output.
        tokenizer: A Hugging Face tokenizer.

    Returns:
        A dict with ``input_ids`` / ``attention_mask`` (and ``text`` for debug).
    """
    messages = build_chat_messages(ex)
    apply = getattr(tokenizer, "apply_chat_template", None)
    if callable(apply):
        text = apply(messages, tokenize=False, add_generation_prompt=False)
    else:  # pragma: no cover - exercised only with a template-less tokenizer
        text = _manual_chat_render(messages)
    enc = tokenizer(text, truncation=True, return_attention_mask=True)
    enc = dict(enc)
    enc["text"] = text
    return enc


def _manual_chat_render(messages: List[Dict[str, str]]) -> str:
    """Fallback Qwen chat rendering when no chat template is registered."""
    out: List[str] = []
    for m in messages:
        out.append(f"<|im_start|>{m['role']}\n{m['content']}<|im_end|>")
    out.append("<|im_start|>assistant\n")
    return "\n".join(out)


def make_collator(tokenizer: Any, max_seq_len: int = 8192) -> Callable[[Any], str]:
    """Return a TRL ``formatting_func``-style callable: ``ex -> chat string``.

    TRL's ``SFTTrainer`` accepts a ``formatting_func`` that maps one dataset row
    to a single training string; it then tokenizes with its own ``max_seq_length``.
    We expose that here (and clamp via the tokenizer when called directly).

    Args:
        tokenizer: HF tokenizer (used for the chat template + truncation length).
        max_seq_len: Max sequence length (recorded for callers that tokenize).

    Returns:
        A callable mapping one example to its formatted chat string.
    """

    def _format(ex: Any) -> str:
        messages = build_chat_messages(ex)
        apply = getattr(tokenizer, "apply_chat_template", None)
        if callable(apply):
            return apply(messages, tokenize=False, add_generation_prompt=False)
        return _manual_chat_render(messages)

    _format.max_seq_len = max_seq_len  # type: ignore[attr-defined]
    return _format


__all__ = [
    "FIXER_TRAIN_SYSTEM",
    "build_chat_messages",
    "format_example",
    "make_collator",
]

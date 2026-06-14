"""Co-resident vLLM launcher for the DualGuard fixer + judge (MG7).

Reads ``config/serve.yaml`` and either PRINTS the exact two launch commands for
the notebook (``--print``) or spawns both servers on the single MI300X. Two
processes at ``--gpu-memory-utilization 0.45`` each prove single-card
co-residency (combined BF16 weights exceed 80GB before the KV cache).

CLI::

    python -m serving.launch_vllm --print                 # emit commands, run nothing
    python -m serving.launch_vllm                          # spawn fixer + judge
    python -m serving.launch_vllm --config config/serve.yaml
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional


_DEFAULTS: Dict[str, Dict[str, Any]] = {
    "fixer": {
        "model": "Qwen/Qwen2.5-Coder-32B-Instruct",
        "served_model_name": "fixer",
        "port": 8000,
        "gpu_memory_utilization": 0.45,
        "max_model_len": 16384,
        "dtype": "bfloat16",
    },
    "judge": {
        "model": "Qwen/Qwen2.5-32B-Instruct",
        "served_model_name": "judge",
        "port": 8001,
        "gpu_memory_utilization": 0.45,
        "max_model_len": 8192,
        "dtype": "bfloat16",
    },
}


def load_serve_config(path: str) -> Dict[str, Dict[str, Any]]:
    """Load config/serve.yaml, falling back to the spec defaults per role."""
    cfg = {"fixer": dict(_DEFAULTS["fixer"]), "judge": dict(_DEFAULTS["judge"])}
    if not path or not os.path.isfile(path):
        return cfg
    try:
        import yaml  # type: ignore
    except ImportError:
        sys.stderr.write(
            "[launch_vllm] warning: pyyaml not installed; using built-in defaults.\n"
        )
        return cfg
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"[launch_vllm] warning: could not read {path}: {exc}\n")
        return cfg
    for role in ("fixer", "judge"):
        section = raw.get(role) or {}
        if isinstance(section, dict):
            cfg[role].update({k: v for k, v in section.items() if k in cfg[role]})
    return cfg


def build_command(role_cfg: Dict[str, Any]) -> List[str]:
    """Build the `vllm serve ...` argv for one role."""
    return [
        "vllm",
        "serve",
        str(role_cfg["model"]),
        "--port",
        str(role_cfg["port"]),
        "--dtype",
        str(role_cfg["dtype"]),
        "--gpu-memory-utilization",
        str(role_cfg["gpu_memory_utilization"]),
        "--max-model-len",
        str(role_cfg["max_model_len"]),
        "--served-model-name",
        str(role_cfg["served_model_name"]),
    ]


def _print_commands(cfg: Dict[str, Dict[str, Any]]) -> None:
    """Print the exact co-resident launch commands (spec §3·MG7, verbatim shape)."""
    fixer = " \\\n  ".join(build_command(cfg["fixer"]))
    judge = " \\\n  ".join(build_command(cfg["judge"]))
    print("# Fixer (terminal 1)")
    print(fixer)
    print()
    print("# Judge (terminal 2, SAME GPU)")
    print(judge)
    print()
    print("# Co-residency proof (terminal 3)")
    print("watch -n 1 rocm-smi --showmeminfo vram --showuse")


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the argparse parser for the launcher CLI."""
    p = argparse.ArgumentParser(
        prog="python -m serving.launch_vllm",
        description=(
            "Launch (or print) the co-resident vLLM fixer + judge on one MI300X."
        ),
    )
    p.add_argument(
        "--config",
        default="config/serve.yaml",
        help="Path to serve.yaml (default: config/serve.yaml).",
    )
    p.add_argument(
        "--print",
        dest="print_only",
        action="store_true",
        help="Print the exact launch commands and exit (spawn nothing).",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. Returns the process exit code."""
    args = build_arg_parser().parse_args(argv)
    cfg = load_serve_config(args.config)

    if args.print_only:
        _print_commands(cfg)
        return 0

    if shutil.which("vllm") is None:
        sys.stderr.write(
            "[launch_vllm] error: `vllm` CLI not found on PATH. This must run on the "
            "AMD MI300X cloud notebook (pip install -r requirements-cloud.txt). "
            "Use --print to emit the commands without launching.\n"
        )
        return 2

    procs: List[subprocess.Popen] = []
    try:
        for role in ("fixer", "judge"):
            cmd = build_command(cfg[role])
            print(f"[launch_vllm] starting {role}: {' '.join(cmd)}")
            procs.append(subprocess.Popen(cmd))
        print(
            "[launch_vllm] both servers spawned on the single GPU. "
            "Prove co-residency with: rocm-smi --showmeminfo vram --showuse"
        )
        # Block until either server exits.
        while procs:
            for proc in list(procs):
                ret = proc.poll()
                if ret is not None:
                    sys.stderr.write(
                        f"[launch_vllm] a vLLM process exited with code {ret}.\n"
                    )
                    return ret or 0
            try:
                procs[0].wait(timeout=5)
            except subprocess.TimeoutExpired:
                continue
    except KeyboardInterrupt:
        print("[launch_vllm] interrupted; terminating servers ...")
    finally:
        for proc in procs:
            if proc.poll() is None:
                proc.terminate()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""MG6 data-prep dataclasses: SFTExample and EvalManifestEntry.

These are the on-disk record shapes for the two data-prep outputs:

    * `SFTExample`        -> one line of the instruction-format SFT JSONL
                             consumed by `training/train_lora.py`.
    * `EvalManifestEntry` -> one line of `data/eval/manifest.jsonl`, consumed by
                             `eval/run_eval.py` (which inflates each entry into a
                             `harness.verdict.BugRecord` after checkout).

These dataclasses are LOCAL to the data-prep package. They are deliberately NOT
the canonical gate contracts: the gate contracts (`BugRecord`, `Patch`,
`LayerResult`, `GateVerdict`) live solely in `harness/verdict.py` and must never
be redefined here. `EvalManifestEntry.source` reuses the same string vocabulary
as `harness.verdict.SourceName` ("vul4j" / "vjbench") so the eval harness can map
an entry straight onto a `BugRecord` without translation.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List


# Mirror of harness.verdict.SourceName. Kept as a plain tuple (not imported) so
# this module has no hard dependency on the harness package being present at
# data-prep time (data prep runs in CI before the gate is wired up). The eval
# harness is responsible for the BugRecord mapping and re-validates the value.
VALID_SOURCES = ("vul4j", "vjbench")


@dataclass
class SFTExample:
    """One supervised fine-tuning example in instruction format.

    Attributes:
        instruction: Fixed task instruction, e.g.
            "Fix this Java vulnerability, return the full patched file".
        input: The full vulnerable Java source file (leak-stripped).
        output: The full patched Java source file (the human fix).
        meta: Non-leaky provenance metadata (project, date, split, dedup key, ...).
            MUST NOT contain CWE ids, CVE ids, file paths, commit hashes, or bug
            ids that would let the model pattern-match the answer.
    """

    instruction: str
    input: str
    output: str
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serializable view (stable key order for reproducible JSONL)."""
        return {
            "instruction": self.instruction,
            "input": self.input,
            "output": self.output,
            "meta": self.meta,
        }


@dataclass
class EvalManifestEntry:
    """One bug in the eval manifest the eval harness consumes.

    Attributes:
        id: Canonical bug id, e.g. "VUL4J-10" or "VJBench-7".
        project: Maven/Gradle project name.
        cwe: CWE identifier string, e.g. "CWE-89" (may be "" if unknown).
        source: Benchmark of origin: "vul4j" or "vjbench" (matches
            harness.verdict.SourceName). VJBench-trans variants keep source
            "vjbench" and set meta/transformed via the `transformed` flag.
        vulnerable_file: Repo-relative path of the file that must be patched.
        pov_tests: Fully-qualified Proof-of-Vulnerability test ids (must FAIL on
            the vulnerable revision), e.g. ["com.example.FooTest#testInjection"].
        human_patch_ref: Reference to the ground-truth human patch (commit hash,
            Vul4J human-patch tag, or relative path) for smoke tests / audit.
        semgrep_covered: True iff `cwe` appears in config/cwe_focus.yaml — i.e.
            the "covered" stratum of the FP&VC-Rate.
        transformed: True for VJBench-trans (anti-memorization) variants.
    """

    id: str
    project: str
    cwe: str
    source: str
    vulnerable_file: str
    pov_tests: List[str] = field(default_factory=list)
    human_patch_ref: str = ""
    semgrep_covered: bool = False
    transformed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serializable view."""
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EvalManifestEntry":
        """Construct from a parsed JSONL line, ignoring unknown keys."""
        known = {
            "id",
            "project",
            "cwe",
            "source",
            "vulnerable_file",
            "pov_tests",
            "human_patch_ref",
            "semgrep_covered",
            "transformed",
        }
        return cls(**{k: v for k, v in d.items() if k in known})

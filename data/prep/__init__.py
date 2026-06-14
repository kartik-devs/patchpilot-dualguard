"""MG6 data-prep package: SFT dataset preparation and eval-manifest assembly.

Public modules:
    schemas      -- SFTExample / EvalManifestEntry dataclasses.
    normalize    -- text normalization + leak-stripping helpers.
    prepare_sft  -- dedup, temporal/by-CVE split, strip leaks, emit instruction JSONL.
    build_eval_set -- assemble the Vul4J/VJBench eval manifest.
"""

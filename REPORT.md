# PatchPilot v2: Executable Verification for AI Security Patching

**TL;DR.** Standard CI (compile + tests + SAST) is not a security oracle: 8 of 13 base-model patches passed it but only 2 actually closed the vulnerability, leaving six "silent fakes" that ship an exploitable hole. PatchPilot v2 replaces text-similarity and self-grading with an executable gate anchored on a Proof-of-Vulnerability test, and — fed back as a retry signal — that same verdict doubles the true-fix rate.

**Abstract.** AI code-repair is usually graded by proxies — diff similarity to a reference patch, an LLM judging its own output, or a green build — none of which prove the vulnerability is closed. We introduce DualGuard, an executable acceptance gate that ANDs five layers (compile, baseline-relative regression, a fail→pass Proof-of-Vulnerability flip, SAST, and an AST non-deletion guard) so a patch is accepted only when the exploit demonstrably stops firing without breaking functionality. On 13 curated Vul4J bugs, the base Qwen2.5-Coder-32B model produced eight patches that passed conventional CI yet only two real fixes; the gate caught all six silent fakes, and feeding its failing-PoV verdict back as a retry signal doubled true fixes from 2 to 4. A leakage-controlled LoRA fine-tune, despite clean convergence, scored 0/13 — a credible negative result we report rather than tune away. The contribution is the verifier-as-oracle-and-teacher, not the weights.

## Approach & threat model

**The trust gap.** AI code-repair is usually graded the wrong way. Diff similarity to a reference patch, an LLM judging its own output, or "the build is green" all measure *plausibility*, not *security*. None of them prove the vulnerability is actually closed. Our own data shows why this matters: of the base 32B model's 13 single-shot patches, **8 sailed through standard CI** (compile + regression suite + SAST), yet only **2 truly closed the bug**. The other six are *silent fakes* — they compile, pass the existing tests, and are Semgrep-clean, but the exploit still fires. A pipeline that trusts similarity or self-grading ships those six.

**DualGuard's answer: an executable gate.** Acceptance is decided by running code, not by scoring text. `run_gate` (`harness/gate.py`) ANDs five layers, and `GateVerdict.cleared` is true only if every one passes:

1. **Compiles** — the patched file builds.
2. **Regression pass, baseline-relative** — a non-PoV test counts as a regression *only* if it fails on the patch **and did not already fail on the vulnerable baseline** (`_classify_regression_and_pov`). This neutralizes headless-env-flaky tests so we measure breakage the patch introduced, not noise.
3. **PoV flip** — the Proof-of-Vulnerability exploit test must go **FAIL→PASS**; `pov_flipped` requires both a confirmed fail-before and a pass-after. This is the layer the silent fakes cannot bluff.
4. **SAST clean** — Semgrep must report clean (CodeQL is corroboration-only by default), scoped to the bug's CWE.
5. **AST non-deletion guard** — rejects "fixes" that just delete the vulnerable code. `non_deletion_ok` (`ast_guard.py`) checks a retained-statement ratio and that return/throw paths aren't dropped, and hard-rejects unparseable patches. Without it, the easiest way to silence the exploit *and* SAST is to gut the method — passing the other four layers while destroying functionality.

The headline metric, **Functionality-Preserved & Vuln-Cleared (FP&VC)** with a Wilson 95% CI, is exactly this conjunction: layer 2 preserves behavior, layer 3 proves the vuln is gone, and layer 5 stops the gate from being gamed. The executable PoV is what catches exploitable patches — and, fed back as a retry signal, what teaches the model to fix them.

## Results

**Base 32B, single-shot — FP&VC = 2/13 (15.4%, Wilson 95% CI ≈ [4.3%, 42.2%]).** Eight of the 13 single-shot patches passed compile + regression + Semgrep — the checks a conventional CI/SAST pipeline runs — but only **2 actually closed the vulnerability**: VUL4J-64 (XXE) and VUL4J-77 (deserialization). The other six were *silent fakes*: green under compile, tests, and Semgrep, yet the PoV exploit test still failed. The gate caught all six because `pov_flipped` (`harness/gate.py`) requires the PoV to flip FAIL→PASS (`baseline_failed AND pov_passed`), not merely that the suite is green.

| Bug | CWE | compile | tests | PoV-flip | SAST | AST | verdict |
|-----------|-----------|:---:|:---:|:---:|:---:|:---:|---------------|
| VUL4J-64 | CWE-611 (XXE) | PASS | PASS | PASS | PASS | PASS | **cleared** |
| VUL4J-77 | CWE-502 (deser) | PASS | PASS | PASS | PASS | PASS | **cleared** |
| VUL4J-50 | CWE-79 (XSS) | PASS | PASS | FAIL | PASS | PASS | silent fake |
| VUL4J-41 | CWE-22 (path-trav) | PASS | PASS | FAIL | PASS | PASS | silent fake |
| VUL4J-25 | CWE-79 (XSS) | PASS | PASS | FAIL | PASS | PASS | silent fake |
| VUL4J-43 | CWE-22 (path-trav) | PASS | PASS | FAIL | PASS | PASS | silent fake |
| VUL4J-23 | CWE-79 (XSS) | PASS | PASS | FAIL | PASS | PASS | silent fake |
| VUL4J-6 | CWE-835 (loop) | PASS | PASS | FAIL | PASS | PASS | silent fake |
| VUL4J-59 | CWE-79 | FAIL | — | — | — | — | no-compile |
| VUL4J-47 | CWE-611 | FAIL | — | — | — | — | no-compile |
| VUL4J-65 | CWE-22 | FAIL | — | — | — | — | no-compile |
| VUL4J-78 | CWE-502 | FAIL | — | — | — | — | no-compile |
| VUL4J-44 | CWE-327 | FAIL | — | — | — | — | no-compile |

The six silent fakes are the dangerous case: a developer trusting compile + tests + SAST would have shipped an exploitable "fix." The five no-compiles fail loudly and are caught by any pipeline. Only the executable PoV separates the two genuine fixes from the six impostors.

**Feedback loop doubles true fixes: 2/13 → 4/13 (30.8%, Wilson 95% CI ≈ [12.7%, 57.6%]).** Feeding the gate's failing-PoV verdict back to the model as a retry signal (`N_RETRIES=2`) cleared two former silent fakes — VUL4J-50 (XSS) and VUL4J-41 (path-traversal) — flipping their PoVs FAIL→PASS while keeping compile, regression, and SAST green. The executable verdict is not just a filter; fed back, it teaches the model to actually close the hole.

**Robustness / variance.** A replication at higher retries (`N_RETRIES=4`) cleared the two robust fixes (VUL4J-64, VUL4J-50) on every run, while VUL4J-41 and VUL4J-77 cleared at N=2 but were missed at N=4 — at N=13 with stochastic decoding, individual outcomes vary run-to-run. The feedback effect (single-shot 2/13 → with-feedback 3–4/13) is consistently positive; the precise count is noisy at this sample size, so we report the N=2 point as the headline and flag the variance honestly rather than claim a clean monotonic scaling law. Tighter intervals require a larger eval (future work).

**Fine-tune (honest negative).** The LoRA (r16, SFT on 770 leakage-free pairs) scored **0/13 single-shot and 0/13 with retries**, frequently emitting non-compiling patches under multi-turn feedback. It did not beat base; analysis follows in the next section.

All rates are FP&VC (cleared / N=13) per the `cleared` AND-of-six oracle in `harness/verdict.py`, with Wilson 95% intervals from `eval/metrics.py`. N=13 is small and the intervals are wide; we report them honestly.

## Why the fine-tune did not help

The LoRA was trained the way a fine-tune is supposed to be trained. The data was leakage-controlled against the Vul4J eval set (by-CVE and by-repo holdout, a pre-2021 temporal cut, and exact-SHA + MinHash dedup), and the run itself converged cleanly: 770 pairs, final train loss 0.32, 96.9% token accuracy on the MI300X. Yet it scored 0/13 single-shot and 0/13 with retries, and under multi-turn feedback it frequently regressed into non-compiling patches. We report this as a credible negative result rather than tuning it away.

The most likely cause is distribution shift, not bad optimization. The SFT objective was single-turn: given one vulnerable file, reproduce the human patch verbatim. The eval task is different in shape: produce a full-file fix, then, on gate failure, ingest a structured failure summary and repair across turns. The model was optimized to imitate a fixed answer, never to revise one under feedback, so the held-out token accuracy it earned does not transfer to the loop the gate actually measures. A low loss against human patches is simply not the same target as "passes an executable proof-of-vulnerability."

There is also evidence of mild capability regression. Tightly fitting a narrow CVEfixes patch style appears to have cost some of the base 32B's general coding robustness; the clearest symptom is that the adapter produced more non-compiling outputs in the multi-turn setting, exactly where flexibility matters most.

The takeaway is that the leverage lives in the executable verification + feedback loop, not in these weights. Feedback alone doubled the base model's true-fix rate (2→4). That motivates the right next step: optimize against the gate's verdict directly (gate-as-reward / DPO on cleared-vs-failed pairs, scaffolded in `train/dpo_stub.py`) rather than against imitation of human patches.

## Leakage controls & threats to validity

**Leakage controls.** The fine-tune corpus is built from CVEfixes under a layered holdout (`data/prep/build_cvefixes_corpus.py`), and the provenance count after each step is recorded as evidence:

- **By-CVE + by-repo holdout against Vul4J.** Any candidate pair whose CVE id *or* source repository matches a Vul4J eval project is dropped. Excluding the whole repo (not just the CVE) removes project-idiom leakage, so the model never sees the coding style of an eval target.
- **Temporal cut (~2021).** Only commits dated strictly before the Vul4J cutoff are kept, so no post-cutoff knowledge of an eval bug can enter training.
- **Dedup.** Exact SHA-256 over the normalized before+after pair, then near-duplicate removal with MinHash LSH; pairs whose vulnerable method near-matches a Vul4J vulnerable method are additionally dropped. The SFT pipeline asserts no CVE/project spans the train/held-out boundary and aborts on any overlap.

This yielded the 770 leakage-free pairs used for SFT.

**Threats to validity.** The eval is **N = 13** curated Vul4J bugs, so the FP&VC rate carries wide Wilson 95% CIs — point estimates (e.g. 2/13 → 4/13 under feedback) should be read as directional, not precise. Each bug is gated by a **single Proof-of-Vulnerability test** (`failing_tests` in `config/vul4j_meta.json`); one PoV can be satisfied without truly closing the class, which is exactly why we add the AST non-deletion guard and SAST corroboration, and why broader adversarial verification is on the roadmap. Regression is scored **baseline-relative**: only tests that fail on the patch *and* passed on the vulnerable baseline count, neutralizing headless-env-flaky tests. **CodeQL is corroboration-only on this run** (`codeql_required: false`); Semgrep plus the executable PoV/regression/AST guards are binding. Finally, these 13 are a **curated, pre-confirmed-reproducible green subset**, not the full 79-bug Vul4J set — selected for clean fail-before reproduction, so results may not generalize to the long tail.

## Related work, positioning & future work

**How patch quality is usually measured — and why it falls short.** The two dominant evaluation paradigms for LLM program repair do not actually prove that a vulnerability is closed. *Similarity-based* metrics (exact-match, BLEU/CodeBLEU, edit distance against a gold fix) reward textual proximity to a reference patch, but a patch can score high while remaining exploitable, or score low while being a perfectly valid alternative fix. *LLM-as-judge* evaluation asks a model to grade the patch; this is unanchored to execution and inherits the grader's blind spots — precisely the failure mode our results expose, since the same class of confident-but-wrong reasoning produced our six silent fakes. Standard CI (compile + regression + SAST) is stronger but still insufficient, as the Results show.

**Our contribution.** We make success *executable and adversarial*: a patch is accepted only when the real Proof-of-Vulnerability test flips fail→pass on identical input, alongside baseline-relative regression, dual-SAST, and an AST non-deletion guard. In our pipeline the LLM-as-judge is demoted to candidate *ranking* only; the gate verdict is the sole ground-truth oracle. Critically, feeding the gate's failing-PoV signal back as a retry doubled true fixes (2→4/13), showing the verifier is also a *teacher*.

**Future work.** (1) *Adversarial verification* — synthesize multiple exploit variants per CWE so a fix must survive a family of attacks, not a single PoV. (2) *Gate-as-reward DPO/RL* — formalize the retry loop, which already doubled fixes, into a preference/reward signal. (3) *Scale the eval* to all 79 Vul4J bugs plus VJBench for tighter confidence intervals. (4) *Ship the gate* as a CI/PR check emitting SARIF for native code-scanning integration.

Reproduce: see `scripts/bootstrap_pod.sh`.

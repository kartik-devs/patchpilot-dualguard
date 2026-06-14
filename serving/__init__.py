"""PatchPilot v2 \"DualGuard\" serving package (MG7).

Contains the canonical prompt builders (:mod:`serving.prompts`) and the
co-resident vLLM launcher (:mod:`serving.launch_vllm`). The in-repo OpenAI
client (:mod:`serve.dualguard`) imports prompt builders from here when present
(falling back to inline copies otherwise). No gate contracts are defined here.
"""

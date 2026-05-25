# Guardian Guardrail Research Notes

Guardian should keep deterministic runtime policy enforcement as the source of
truth. Open models and guardrail engines are most useful as benchmark,
adversarial corpus, and optional sidecar inputs until their false positive and
latency profiles are measured against Guardian traces.

## Runtime Design References

- LlamaFirewall: layered agent guardrail scanners for prompt injection,
  alignment checks, code risk, and regex rules. Useful model for combining
  deterministic scanners with optional ML signals.
  https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall
- NeMo Guardrails: programmable rails and evaluation workflows. Useful for
  thinking about policy composition and eval structure, but not a replacement
  for Guardian's local tool enforcement.
  https://github.com/NVIDIA-NeMo/Guardrails
- Guardrails AI: validator composition and guard execution framework. Useful as
  a pattern for a future pluggable scanner interface.
  https://github.com/guardrails-ai/guardrails
- Open Policy Agent and Cedar: mature policy engines. Useful references if
  Guardian profiles outgrow static action-type maps.
  https://github.com/open-policy-agent/opa
  https://github.com/cedar-policy/cedar

## Open Models For Corpus Generation

- Prompt Guard 2: prompt injection and jailbreak detection. Use to seed
  indirect-injection strings that may later produce risky tool calls.
  https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M
- Llama Guard 4: broad content and tool-abuse safety classifier. Use as a
  semantic benchmark, not as a shell/file decision source.
  https://huggingface.co/meta-llama/Llama-Guard-4-12B
- Granite Guardian: risk detection for agentic and enterprise workflows,
  including function calling. Use for comparing tool-call risk labels.
  https://huggingface.co/ibm-granite/granite-guardian-3.2-3b-a800m

## Red Team And Eval Tools

- garak: LLM vulnerability scanner covering jailbreaks, leakage, prompt
  injection, and encoding attacks. Use for adversarial prompt corpora.
  https://github.com/NVIDIA/garak
- PyRIT: Microsoft generative AI red-team automation framework. Use for
  scenario generation and repeatable attack workflows.
  https://github.com/microsoft/PyRIT
- AgentDojo: prompt-injection benchmark for tool-using agents. Use for
  tool-call attack patterns that should become Guardian fixtures.
  https://github.com/ethz-spylab/agentdojo

## Parser Reference

- mvdan/sh: Go shell parser, formatter, and interpreter. Guardian uses the
  syntax parser as an AST-backed conservative validation layer before applying
  local command taxonomy.
  https://github.com/mvdan/sh


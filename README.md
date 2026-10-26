# Sentry-Vision-
standalone Meta Llama-powered Solidity Contract Verifier

# Problem: 

Developers or non-technical founder get either complex Slither reports they don't understand, or generic LLM answers they can't trust.

# Solution:

1. Developer uploads/pastes a .sol contract

2. Slither performs deterministic
static detection

3. Meta Llama triages the findings, eliminates false positives, explains exploitability, and generates an attack scenario

4. App returns structured JSON + a visual attack flowchart (Mermaid rendered from Llama output)

5. Llama generates a patched version + secure flowchart

* Core Differentiation: Not just "find bugs" — visualize how the hack would actually happen.

* Llama JSON schema -> Slither + Llama + Mermaid pipeline

# Sentry-Vision-
standalone Meta Llama-powered Solidity Contract Verifier

 ##Problem: 

Developers or non-technical founder get either complex Slither reports they don't understand, or generic LLM answers they can't trust.

 ##Solution:

1. Developer uploads/pastes a .sol contract

2. Slither performs deterministic
static detection

3. Meta Llama triages the findings, eliminates false positives, explains exploitability, and generates an attack scenario

4. App returns structured JSON + a visual attack flowchart (Mermaid rendered from Llama output)

5. Llama generates a patched version + secure flowchart

* Core Differentiation: Not just "find bugs" — visualize how the hack would actually happen.

##Core Architecture

   1. User uploads .sol
        ↓
2. Slither (Python) -> detectors + call graph + function list
        ↓
3. Feed Slither JSON + source code to Llama
   Prompt: "Triage these findings, remove false positives,
            rank by exploitability, generate attack_flow[] and fix"
        ↓
4. Llama returns YOUR final clean JSON
        ↓
5. Your code turns attack_flow[] into Mermaid (Red diagram)
   Your code turns fixed code into Mermaid (Green diagram)

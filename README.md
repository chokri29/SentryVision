# Sentry Vision

**Meta Llama–powered Solidity pre-audit verifier for non-technical founders.**

Built during the Meta AI Developer Hackathon.

---

## Problem

Founders and early teams usually get one of two things:

- **Dense static-analysis dumps** (e.g. raw Slither) they cannot interpret, or  
- **Generic LLM answers** with no deterministic grounding they can trust.

Neither helps a non-technical person decide *what is actually dangerous* and *how an exploit would unfold*.

---

## Solution

1. Developer uploads or pastes a `.sol` contract.  
2. **Slither** runs deterministic static detection (detectors, impact, relevant lines).  
3. **Meta Llama / Muse** triages those findings: drops obvious noise, ranks by exploitability, and explains each issue in plain language.  
4. The app returns **structured JSON** plus a **visual attack flowchart** (Mermaid, rendered in the UI).  
5. *(Stretch)* Optional patched snippet and a “secure flow” diagram — not required for the core demo.

**Core differentiation:** not only “find bugs” — **show how the hack would actually happen.**

---

## Core architecture

```text
1. User pastes / uploads .sol
        ↓
2. Slither (Python) → detectors + impact + function / line hints
        ↓
3. Slither JSON + source → Meta Llama / Muse
   Prompt: triage findings, remove false positives,
           rank by exploitability, explain for a founder,
           emit attack_flow + optional fix hints
        ↓
4. Llama returns clean structured JSON
        ↓
5. App renders:
   • Finding cards (severity, what happens, why it matters, what to do)
   • Mermaid attack flowchart (exploit path)
   • Optional “after fix” diagram (stretch)
```

| Layer | Role | Engine |
|------|------|--------|
| **F1** | Deterministic static signal | Sli ther |
| **F2** | Triage + founder-facing explanation | Meta Llama / Muse |
| **F3** | Visual exploit path | Mermaid.js |

---

## Status

Event scaffold — README and architecture locked. Implementation commits follow during the hackathon window.

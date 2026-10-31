# Sentry Vision

**SentryVision is a standalone smart contract security verifier built for the Meta Hackathon. It analyzes Solidity contracts, identifies vulnerabilities, explains how an exploit would actually happen, and visualizes the attack flow.**

Unlike generic scanners that output cryptic reports, SentryVision combines deterministic static analysis with Meta's Muse Spark Open (and optional Muse Wonder on repair) to produce structured, auditable, and visual security intelligence.

> Sentry Vision is a triage and visualization tool, **not** a formal security audit. See [Limitations](#limitations).

---

## Why not just Slither, or just an LLM?

- **Slither** is a reliable deterministic detector, but its output is hard to read.
- **LLMs** are easy to read, but they can hallucinate.
- **Sentry Vision combines them:** Slither detects, Muse Spark Open interprets and visualizes, Slither re-checks the proposed fix, and optional Muse Wonder retries a rejected patch once.

---

## Problem

Developers and non-technical founders usually get one of two things:

- **Dense static-analysis dumps** (for example raw Slither output) that they cannot interpret, or
- **Generic LLM answers** with no deterministic grounding that they cannot trust.

Neither tells them *what is actually dangerous* or *how an attack would really happen*.

## Solution

1. The user pastes or uploads a `.sol` contract.
2. **Slither** runs deterministic static detection (detector, impact, confidence, affected lines).
3. **Muse Spark Open** triages the findings in plain language and proposes a patch.
4. The app returns **structured JSON** and renders a **visual attack flowchart** (Mermaid).
5. **Slither re-runs on the patch** and a **public signature surface check** runs.
6. If F3 rejects the patch, the user can **retry once** (Muse Wonder when configured).

**Core differentiation:** not just "find bugs", but *show how the hack would happen*, and check the fix with the same deterministic tool — without claiming a formal audit.

---

## How it works

| Layer | Role | Engine |
| --- | --- | --- |
| **F1** | Deterministic static signal | Slither |
| **F2** | Triage, explanation, patch, Mermaid | Muse Spark Open via Baseten |
| **F3** | Patch re-scan + surface check | Slither + signature surface |
| **Retry** (optional) | One user-triggered repair if F3 rejects | Muse Wonder when `LLM_RETRY_MODEL` is set |

```mermaid
flowchart TD
    A["Solidity contract (.sol)"] --> B["F1: Slither static analysis"]
    B --> C["Slither JSON findings"]
    C --> D["F2: Muse Spark Open triage"]
    A --> D
    D --> E["Structured JSON findings + Mermaid flows"]
    E --> G["Finding cards"]
    D --> H["Patch proposal"]
    H --> I["F3: Slither re-verification"]
    I --> G
    I -->|"Rejected: user clicks Retry once"| J["Optional: Muse Wonder repair"]
    J --> K["F3: Slither re-check"]
    K --> G
```

### Verification claim (honest)

Green **Passed Slither re-scan + surface check** means:

1. The patch **compiles** under the pinned solc.
2. Slither reports **no High/Medium** on the patch.
3. Every original public/external entry point **name + parameter types** (plus `receive`/`fallback`) is still present.
4. The behaviour-lite check rejects clear empty or always-reverting bodies when the original entry point had non-gutted logic.

It does **not** mean the contract is safe, that behaviour is preserved, or that Low/Informational issues are gone.

### Vendored OpenZeppelin (subset)

F1 can resolve only the documented `SUPPORTED_OZ_IMPORTS` list through `vendor/openzeppelin/`, a **vendored OZ subset** of hand-written stubs. The stubs use **pre-5.0 style** patterns but are not a copy of a specific upstream version, are not audited upstream code, and are not claimed equivalent to real OZ. Unknown imports fail closed to **Model-only result — not verified**. Expand the supported list only on demand.

### Bounded self-heal (optional retry)

When F3 **rejects** a real patch (`still_vulnerable`, `compile_failed`, `surface_removed`, `gutted_function`, or `regression_introduced`), the UI can offer **one** user-triggered retry:

| Piece | Behavior |
| --- | --- |
| **Trigger** | User clicks **Retry patch once** (never auto) |
| **Server state** | `meta.analysis_id` — original source + findings in memory (~1h TTL) |
| **Endpoint** | `POST /analyze/{analysis_id}/retry-patch` |
| **Cap** | `MAX_PATCH_RETRIES=1` server-side |
| **Default model** | Muse Spark (same as F2) |
| **Optional Wonder** | Set `LLM_RETRY_MODEL` / `LLM_WONDER_MODEL` |

Retry does **not** run on identical patches, empty patches, or pure infra failures. The pass label means only the claim above — not "safe to deploy."

## Meta models used

- **Muse Spark Open** — default F2 triage / patch proposal.
- **Muse Wonder** (optional) — stronger one-shot repair on user-triggered retry.

## Tech stack

- Meta Muse Spark Open via Baseten (optional Muse Wonder on retry)
- [Slither](https://github.com/crytic/slither) + `solc-select` (Docker)
- Python, FastAPI, Pydantic
- HTML / JS + [Mermaid.js](https://mermaid.js.org/)
- Render (Docker)

## Getting started

```bash
git clone https://github.com/chokri29/SentryVision.git
cd SentryVision
cp .env.example .env   # set LLM_API_KEY, optional LLM_RETRY_MODEL
docker build -t sentryvision .
docker run --rm -p 8000:8000 --env-file .env sentryvision
```

- UI: http://localhost:8000
- Health: `GET /health`
- Analyze: `POST /analyze`
- Retry: `POST /analyze/{analysis_id}/retry-patch` (max 1)

## Demo for judges

1. Open the live app.
2. Click **Reentrancy** → **Run Meta-assisted Audit**.
3. Look for pipeline label, findings, Mermaid, and the green **Passed Slither re-scan + surface check** badge (or an honest failure / model-only label).

## Limitations

- Not a professional audit.
- F3 claim is compile + Slither re-scan clean (no High/Medium) + name + parameter types surface preserved + behaviour-lite passed. It does not establish behavioural preservation or security.
- A green pytest suite is test evidence, not proof of complete verification.
- OZ support is a **vendored OZ subset** with documented supported import paths; it is not audited upstream code and is not claimed equivalent to real OpenZeppelin.
- Retry store is in-memory.

## Credits

- [Slither](https://github.com/crytic/slither) by Trail of Bits
- [Mermaid.js](https://mermaid.js.org/)
- Meta — Muse Spark Open + Meta Wonder 
- Baseten — inference credits and hosting

## License

MIT (add a `LICENSE` file when ready).

## Author

Chokri AlGhanmi ([@chokri29](https://github.com/chokri29))



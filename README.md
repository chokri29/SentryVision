# Sentry Vision

**SentryVision is a standalone smart contract security verifier built for the Meta Hackathon. It analyzes Solidity contracts, identifies vulnerabilities, explains how an exploit would actually happen, and visualizes the attack flow.**

Unlike generic scanners that output cryptic reports, SentryVision combines deterministic static analysis with Meta's Muse Spark Open reasoning to produce structured, auditable, and visual security intelligence.

> Sentry Vision is a triage and visualization tool, **not** a formal security audit. See [Limitations](#limitations).

---

## Why not just Slither, or just an LLM?

- **Slither** is a reliable deterministic detector, but its output is hard to read.
- **LLMs** are easy to read, but they can hallucinate.
- **Sentry Vision combines them:** Slither detects, a Meta model interprets and visualizes, and Slither verifies the fix.

---

## Problem

Developers and non-technical founders usually get one of two things:

- **Dense static-analysis dumps** (for example raw Slither output) that they cannot interpret, or
- **Generic LLM answers** with no deterministic grounding that they cannot trust.

Neither tells them *what is actually dangerous* or *how an attack would really happen*.

## Solution

1. The user pastes or uploads a `.sol` contract.
2. **Slither** runs deterministic static detection (detector, impact, confidence, affected lines).
3. **Muse Spark Open** (Meta's open-weights model) triages the findings: confirms real issues, ranks by exploitability, and explains each issue in plain language.
4. The app returns **structured JSON** and renders a **visual attack flowchart** (Mermaid) for each confirmed finding.
5. The model proposes a **patched version**, and **Slither re-runs on the patch** to check it. The result is labeled "Patch verified by Slither" or "Unverified patch".

**Core differentiation:** not just "find bugs", but *show how the hack would actually happen*, and check the fix with the same deterministic tool.

---

## How it works

| Layer | Role | Engine |
| --- | --- | --- |
| **F1** | Deterministic static signal | Slither |
| **F2** | Triage, plain-language explanation, patch proposal | Muse Spark Open (`meta-models/muse-spark-open-1026`) via Baseten |
| **F3** | Patch re-verification + visual exploit path | Slither re-check + Mermaid.js |

```mermaid
flowchart TD
    A["Solidity contract (.sol)"] --> B["F1: Slither static analysis"]
    B --> C["Slither JSON findings"]
    C --> D["F2: Muse Spark Open triage"]
    A --> D
    D --> E["Structured JSON findings"]
    E --> F["Mermaid exploit-flow diagrams"]
    F --> G["Finding cards and attack flowchart"]
    D --> H["Patch proposal"]
    H --> I["F3: Slither re-verification"]
    I --> G
```

### Verification Schema

**F1 - Deterministic Detection:** Slither static analysis on the submitted `.sol` contract produces structured JSON findings.

**F2 - Muse Spark Open Triage:** Meta Muse Spark Open reads both the contract and Slither findings and returns structured JSON findings plus a patch proposal.

**F3 - Presentation & Verification:**
- Finding cards with severity, plain language, and Mermaid exploit flows
- Reasoning-aware parsing with Pydantic validation and one repair retry
- Verified patches: proposed fixes are re-analyzed by Slither before they are labeled verified

---

## Meta models used

- **Muse Spark Open** (`meta-models/muse-spark-open-1026`), Meta's open-weights model, is the core reasoning engine (via Baseten OpenAI-compatible API).
- **Development:** Muse Spark Open was also used as a coding assistant while building this project.

---

## Tech stack

- **Core AI Engine:** Meta Muse Spark Open via Baseten Inference
- **Static Analysis:** [Slither](https://github.com/crytic/slither) with `solc-select` (Docker image)
- **Backend:** Python, FastAPI, Pydantic
- **Frontend:** HTML / JavaScript with [Mermaid.js](https://mermaid.js.org/)
- **Deployment:** Render (Docker)

---

## Getting started

### Prerequisites

- Python 3.10+ **or** Docker
- Baseten API key for Muse Spark Open

### Setup (local Python)

```bash
git clone https://github.com/chokri29/SentryVision.git
cd SentryVision

python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Configuration

```bash
cp .env.example .env
```

```env
LLM_API_KEY=your_baseten_api_key
LLM_BASE_URL=https://inference.baseten.co/v1
LLM_MODEL=meta-models/muse-spark-open-1026
ENABLE_SLITHER=true
ALLOWED_ORIGINS=http://localhost:8000
```

**Never commit `.env`.** On Render, set the same variables in the service dashboard.

### Run

```bash
# Docker (recommended — includes solc + Slither)
docker build -t sentryvision .
docker run --rm -p 8000:8000 --env-file .env sentryvision

# Or local (Slither optional if installed)
uvicorn main:app --reload --port 8000
```

- UI: http://localhost:8000
- Health: `GET /health`
- API: `POST /analyze` with `{ "solidity_code": "..." }`

---

## Demo for judges (3 clicks)

1. Open the live app (or `http://localhost:8000` after Docker/local start).
2. Click **examples/01 · Reentrancy** (same source as [`examples/01_reentrancy.sol`](examples/01_reentrancy.sol)).
3. Click **Run AI Audit**.

**What to look for**

| UI signal | Meaning |
| --- | --- |
| Summary meta line | `Slither findings: N · Patches verified: M · Pipeline: F1 → F2 → F3` |
| Finding severity + plain language | F2 Muse triage grounded in F1 |
| Mermaid flowchart | Visual exploit path for non-technical founders |
| **Patch verified by Slither** (green) | F3 re-ran Slither on the proposed fix — deterministic check |
| **Fix proposed** | Muse returned a full patched contract |

Optional: try **examples/02 · Access Control** and **examples/03 · Unchecked Call**. Source for every button lives under [`examples/`](examples/) so judges can open the same files in the repo.

---

## Regression fixtures (`examples/`)

| File | UI sample | Expected primary issues |
| --- | --- | --- |
| [`01_reentrancy.sol`](examples/01_reentrancy.sol) | examples/01 · Reentrancy | Reentrancy (external call before balance update) |
| [`02_missing_access_control.sol`](examples/02_missing_access_control.sol) | examples/02 · Access Control | Missing access control on `emergencyWithdraw` |
| [`03_unchecked_call.sol`](examples/03_unchecked_call.sol) | examples/03 · Unchecked Call | Unchecked low-level call / CEI-style issues |
| [`04_tx_origin_auth.sol`](examples/04_tx_origin_auth.sol) | — | `tx.origin` authentication |
| [`05_safe_minimal.sol`](examples/05_safe_minimal.sol) | — | Ideally no Critical/High findings |

These contracts are self-contained (no OpenZeppelin imports) so Slither can run in the Docker image. They are **demo / triage fixtures**, not formal audit ground truth.

---

## Hackathon progress

Everything in this repository is being built during the hackathon window. An earlier pre-hackathon prototype exists in a separate private repository and is **not** part of this submission.

| Milestone | Status |
| --- | --- |
| FastAPI endpoint and Muse Spark Open call (via Baseten) | Done |
| UI (`index.html`) with finding cards + Mermaid flows | Done |
| F1 Slither runner (Docker + solc) | Done |
| F2 Muse triage + plain-language findings | Done |
| F3 patch proposal + Slither re-verification | Done |
| Sample contracts aligned with UI buttons | Done |
| Live deploy on Render | Done |
| Improvements and Refining | Planned |
| Testing Accuracy and outputs Validation | Planned |

The commit history shows when each piece was built.

---

## Limitations

- This is **not a formal audit** and gives no guarantee that a contract is safe.
- Slither can produce false positives, and no static analyzer finds every bug. The model can also be wrong.
- A patch marked "verified by Slither" only means Slither no longer reports High/Medium findings on that patch, not that the contract is secure.
- Contracts that depend on external imports may not compile when pasted as a single file.
- Always have important contracts reviewed by a professional auditor before deployment.

---

## Roadmap

- Multi-file and import support
- Secure-flow diagram showing the path after the fix
- Upload an architecture screenshot for analysis (Muse Spark Open supports vision)
- Integration into the digital assets security verification project [cryptoreviewlab.com](https://cryptoreviewlab.com) review workflow
- CryptoReviewLab [Repository](https://github.com/chokri29/Crypto-Review-Lab)

---

## Credits

- [Slither](https://github.com/crytic/slither) by Trail of Bits
- [Mermaid.js](https://mermaid.js.org/)
- Meta — Muse Spark Open and the hackathon
- Baseten — inference credits and hosting

## License

MIT (add a `LICENSE` file when ready).

## Author

Chokri AlGhanmi ([@chokri29](https://github.com/chokri29))

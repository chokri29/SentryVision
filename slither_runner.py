"""F1: run Slither on a single-file Solidity source and return compact findings.

Graceful: if Slither/solc is missing or fails, returns ([], error_message)
so the Muse-only path still works.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger("sentryvision.slither")

# Keep Muse focused on real security detectors, not style noise.
KEEP_IMPACTS = {"High", "Medium", "Critical"}

# Prefer these detectors even if impact tagging is odd.
PRIORITY_CHECKS = {
    "reentrancy-eth",
    "reentrancy-no-eth",
    "reentrancy-benign",
    "reentrancy-events",
    "reentrancy-unlimited-gas",
    "controlled-delegatecall",
    "delegatecall-loop",
    "unchecked-lowlevel",
    "unchecked-send",
    "arbitrary-send-eth",
    "arbitrary-send-erc20",
    "suicidal",
    "tx-origin",
    "unprotected-upgrade",
    "locked-ether",
    "void-cst",
    "rtlo",
    "shadowing-state",
    "uninitialized-state",
    "uninitialized-storage",
    "uninitialized-local",
    "arbitrary-send",
    "controlled-array-length",
    "msg-value-loop",
}

DROP_CHECKS = {
    "naming-convention",
    "solc-version",
    "pragma",
    "external-function",
    "low-level-calls",  # often noisy; unchecked-* covers the real risk
    "too-many-digits",
    "constable-states",
    "immutable-states",
    "var-read-using-this",
    "dead-code",
    "unused-state",
    "unused-return",
    "similar-names",
}

SLITHER_TIMEOUT_SECONDS = int(os.getenv("SLITHER_TIMEOUT_SECONDS", "60"))
ENABLE_SLITHER = os.getenv("ENABLE_SLITHER", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}


def slither_available() -> bool:
    if not ENABLE_SLITHER:
        return False
    return shutil.which("slither") is not None


def _extract_detectors(payload: Any) -> list[dict]:
    """Normalize Slither JSON shapes into a flat detector list."""
    if not isinstance(payload, dict):
        return []

    results = payload.get("results")
    if isinstance(results, dict):
        detectors = results.get("detectors")
        if isinstance(detectors, list):
            return [d for d in detectors if isinstance(d, dict)]

    detectors = payload.get("detectors")
    if isinstance(detectors, list):
        return [d for d in detectors if isinstance(d, dict)]

    return []


def _compact_finding(det: dict) -> dict:
    check = str(det.get("check") or det.get("id") or "unknown")
    impact = str(det.get("impact") or "Informational")
    confidence = str(det.get("confidence") or "")
    description = str(det.get("description") or "").strip()
    # Keep description short for the LLM context window.
    if len(description) > 500:
        description = description[:497] + "..."

    elements = []
    for el in det.get("elements") or []:
        if not isinstance(el, dict):
            continue
        source = el.get("source_mapping") or {}
        lines = source.get("lines") or []
        name = el.get("name") or el.get("type") or ""
        if lines:
            elements.append(f"{name} @ lines {lines[0]}-{lines[-1]}".strip())
        elif name:
            elements.append(str(name))

    return {
        "check": check,
        "impact": impact,
        "confidence": confidence,
        "description": description,
        "elements": elements[:6],
    }


def filter_findings(raw: list[dict]) -> list[dict]:
    kept: list[dict] = []
    seen: set[str] = set()

    for det in raw:
        check = str(det.get("check") or "").lower()
        impact = str(det.get("impact") or "Informational")

        if check in DROP_CHECKS:
            continue

        keep = check in PRIORITY_CHECKS or impact in KEEP_IMPACTS
        if not keep:
            continue

        compact = _compact_finding(det)
        key = f"{compact['check']}|{compact['description'][:80]}"
        if key in seen:
            continue
        seen.add(key)
        kept.append(compact)

    # Prefer higher impact first.
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    kept.sort(key=lambda d: order.get(d.get("impact", "Informational"), 9))
    return kept[:20]


def run_slither(solidity_code: str) -> tuple[list[dict], str | None]:
    """Run Slither on solidity_code.

    Returns (filtered_findings, error_or_none).
    On any failure returns ([], reason) so callers can fall back to Muse-only.
    """
    if not ENABLE_SLITHER:
        return [], "Slither disabled via ENABLE_SLITHER"

    if not shutil.which("slither"):
        return [], "slither binary not found on PATH"

    tmp_dir = None
    try:
        tmp_dir = tempfile.mkdtemp(prefix="sentryvision_slither_")
        sol_path = Path(tmp_dir) / "Contract.sol"
        sol_path.write_text(solidity_code, encoding="utf-8")

        cmd = [
            "slither",
            str(sol_path),
            "--json",
            "-",
            "--disable-color",
        ]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SLITHER_TIMEOUT_SECONDS,
            cwd=tmp_dir,
        )

        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()

        # Slither often exits non-zero when findings exist; still parse JSON.
        payload = None
        if stdout:
            try:
                payload = json.loads(stdout)
            except json.JSONDecodeError:
                # Sometimes tools mix log lines; try last JSON object.
                start, end = stdout.find("{"), stdout.rfind("}")
                if start != -1 and end > start:
                    try:
                        payload = json.loads(stdout[start : end + 1])
                    except json.JSONDecodeError:
                        payload = None

        if payload is None:
            reason = stderr[:300] if stderr else f"Slither exit {proc.returncode}, no JSON"
            logger.warning("Slither failed: %s", reason)
            return [], reason

        raw = _extract_detectors(payload)
        filtered = filter_findings(raw)
        logger.info("Slither: %d raw detectors, %d after filter", len(raw), len(filtered))
        return filtered, None

    except subprocess.TimeoutExpired:
        logger.warning("Slither timed out after %ss", SLITHER_TIMEOUT_SECONDS)
        return [], f"Slither timed out after {SLITHER_TIMEOUT_SECONDS}s"
    except Exception as exc:
        logger.exception("Slither runner error")
        return [], str(exc)
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


def format_slither_for_prompt(findings: list[dict]) -> str:
    if not findings:
        return "No high/medium Slither detectors fired (or Slither unavailable)."

    lines = ["Slither static analysis (filtered high/medium detectors):"]
    for i, f in enumerate(findings, 1):
        els = ", ".join(f.get("elements") or []) or "n/a"
        lines.append(
            f"{i}. [{f.get('impact')}] {f.get('check')} — {f.get('description')} "
            f"(elements: {els})"
        )
    return "\n".join(lines)

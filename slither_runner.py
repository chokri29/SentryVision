"""SentryVision - Sli ther Runner

F1: Deterministic static analysis
Also used for F3 verified patches (re-scan proposed fixes).

Merged design:
- Muse Spark structure: JSON file output, solc-select, verify_patch, rich result dict
- Noise filter + prompt formatter + ENABLE_SLITHER flag for safe Muse grounding
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("sentryvision.slither")

SLITHER_TIMEOUT = int(os.getenv("SLITHER_TIMEOUT_SECONDS", "120"))
ENABLE_SLITHER = os.getenv("ENABLE_SLITHER", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

# Keep Muse focused on real security detectors, not style noise.
KEEP_IMPACTS = {"High", "Medium", "Critical"}

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
    "low-level-calls",
    "too-many-digits",
    "constable-states",
    "immutable-states",
    "var-read-using-this",
    "dead-code",
    "unused-state",
    "unused-return",
    "similar-names",
}


# ------------------------------------------------------------------
# Availability
# ------------------------------------------------------------------
def is_slither_available() -> bool:
    if not ENABLE_SLITHER:
        return False
    try:
        result = subprocess.run(
            ["slither", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


# Backwards-compatible name used by main.py health check
def slither_available() -> bool:
    return is_slither_available()


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def _safe_filename(contract_name: str) -> str:
    name = Path(contract_name or "Contract.sol").name
    name = re.sub(r"[^a-zA-Z0-9_.-]", "_", name)
    return name if name.endswith(".sol") else f"{name}.sol"


def _try_set_solc_version(source_code: str) -> None:
    """Best effort: if code has `pragma solidity 0.8.20`, try to use it."""
    match = re.search(r"pragma\s+solidity\s+[^;]*?(\d+\.\d+\.\d+)", source_code)
    if not match:
        return
    version = match.group(1)
    try:
        subprocess.run(
            ["solc-select", "use", version, "--always-install"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception as exc:
        logger.warning("solc-select failed for %s: %s", version, exc)


def _normalize_detectors(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    detectors = raw.get("results", {}).get("detectors", []) or []
    normalized: List[Dict[str, Any]] = []

    for d in detectors:
        elements = d.get("elements", []) or []
        lines: List[int] = []
        first_file = None

        for el in elements:
            sm = el.get("source_mapping", {}) or {}
            lines.extend(sm.get("lines", []) or [])
            if not first_file and sm.get("filename_relative"):
                first_file = sm.get("filename_relative")

        description = (d.get("description") or "").strip()
        if len(description) > 500:
            description = description[:497] + "..."

        normalized.append(
            {
                "check": d.get("check"),
                "impact": d.get("impact"),
                "confidence": d.get("confidence"),
                "description": description,
                "markdown_element": d.get("markdown_element"),
                "first_markdown_element": d.get("first_markdown_element"),
                "file": first_file,
                "lines": sorted(set(lines)),
                "elements": [
                    {
                        "name": el.get("name"),
                        "type": el.get("type"),
                        "source_mapping": el.get("source_mapping"),
                    }
                    for el in elements
                ],
            }
        )

    return normalized


def filter_findings(raw: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop style noise; keep high/medium impact and priority security checks."""
    kept: List[Dict[str, Any]] = []
    seen: set[str] = set()

    for det in raw:
        check = str(det.get("check") or "").lower()
        impact = str(det.get("impact") or "Informational")

        if check in DROP_CHECKS:
            continue

        keep = check in PRIORITY_CHECKS or impact in KEEP_IMPACTS
        if not keep:
            continue

        key = f"{check}|{(det.get('description') or '')[:80]}"
        if key in seen:
            continue
        seen.add(key)
        kept.append(det)

    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    kept.sort(key=lambda d: order.get(str(d.get("impact") or "Informational"), 9))
    return kept[:20]


def format_slither_for_prompt(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return "No high/medium Slither detectors fired (or Slither unavailable)."

    lines = ["Slither static analysis (filtered high/medium detectors):"]
    for i, f in enumerate(findings, 1):
        lines_info = f.get("lines") or []
        els = []
        for el in f.get("elements") or []:
            name = el.get("name") or el.get("type") or ""
            if name:
                els.append(str(name))
        if lines_info:
            loc = f"lines {lines_info[0]}-{lines_info[-1]}"
        else:
            loc = ", ".join(els[:4]) if els else "n/a"
        lines.append(
            f"{i}. [{f.get('impact')}] {f.get('check')} — {f.get('description')} "
            f"({loc})"
        )
    return "\n".join(lines)


# ------------------------------------------------------------------
# Core Runner
# ------------------------------------------------------------------
def run_slither(
    source_code: str, contract_name: str = "Contract.sol"
) -> Optional[Dict[str, Any]]:
    """Run Slither on source code string.

    Returns:
        {
          "success": bool,
          "detectors": [normalized findings],
          "filtered_detectors": [noise-filtered subset for Muse],
          "detector_checks": ["reentrancy-eth", ...],
          "count": int,
          "filtered_count": int,
          "raw": {...} | None,
          "error": str | None
        }
    Returns None only if Slither is not installed / disabled.
    """
    if not source_code or not source_code.strip():
        return {
            "success": False,
            "detectors": [],
            "filtered_detectors": [],
            "detector_checks": [],
            "count": 0,
            "filtered_count": 0,
            "raw": None,
            "error": "Empty source code",
        }

    if not is_slither_available():
        logger.warning("Slither not available in this environment")
        return None

    _try_set_solc_version(source_code)

    with tempfile.TemporaryDirectory(prefix="sentryvision_") as tmp:
        tmp_path = Path(tmp)
        sol_file = tmp_path / _safe_filename(contract_name)
        out_file = tmp_path / "slither.json"
        sol_file.write_text(source_code, encoding="utf-8")

        cmd = ["slither", str(sol_file), "--json", str(out_file)]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=SLITHER_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "detectors": [],
                "filtered_detectors": [],
                "detector_checks": [],
                "count": 0,
                "filtered_count": 0,
                "raw": None,
                "error": f"Slither timed out after {SLITHER_TIMEOUT}s",
            }
        except Exception as exc:
            return {
                "success": False,
                "detectors": [],
                "filtered_detectors": [],
                "detector_checks": [],
                "count": 0,
                "filtered_count": 0,
                "raw": None,
                "error": str(exc),
            }

        # Slither exits non-zero when findings exist — JSON file is source of truth.
        if not out_file.exists():
            return {
                "success": False,
                "detectors": [],
                "filtered_detectors": [],
                "detector_checks": [],
                "count": 0,
                "filtered_count": 0,
                "raw": None,
                "error": (proc.stderr or proc.stdout or "Slither produced no JSON output")[
                    :2000
                ],
            }

        try:
            raw = json.loads(out_file.read_text(encoding="utf-8"))
        except Exception as exc:
            return {
                "success": False,
                "detectors": [],
                "filtered_detectors": [],
                "detector_checks": [],
                "count": 0,
                "filtered_count": 0,
                "raw": None,
                "error": f"Invalid Slither JSON: {exc}",
            }

        if not raw.get("success", True):
            return {
                "success": False,
                "detectors": [],
                "filtered_detectors": [],
                "detector_checks": [],
                "count": 0,
                "filtered_count": 0,
                "raw": raw,
                "error": str(raw.get("error"))[:2000],
            }

        detectors = _normalize_detectors(raw)
        filtered = filter_findings(detectors)
        return {
            "success": True,
            "detectors": detectors,
            "filtered_detectors": filtered,
            "detector_checks": sorted(
                {d["check"] for d in detectors if d.get("check")}
            ),
            "count": len(detectors),
            "filtered_count": len(filtered),
            "raw": raw,
            "error": None,
        }


def run_slither_on_code(
    source_code: str, contract_name: str = "Contract.sol"
) -> Optional[Dict[str, Any]]:
    """Backwards-compatible alias."""
    return run_slither(source_code, contract_name)


# ------------------------------------------------------------------
# Verified Patches (F3)
# ------------------------------------------------------------------
def verify_patch(
    patched_code: str,
    target_checks: Optional[List[str]] = None,
    contract_name: str = "Patched.sol",
) -> Dict[str, Any]:
    """Re-analyze a Muse-proposed patch with Slither."""
    if not patched_code or not patched_code.strip():
        return {
            "patch_verified": False,
            "patch_verification_status": "not_checked",
            "patch_verification_details": "No patched code provided.",
            "remaining_checks": [],
        }

    result = run_slither(patched_code, contract_name)

    if result is None:
        return {
            "patch_verified": False,
            "patch_verification_status": "slither_unavailable",
            "patch_verification_details": (
                "Patch generated by Muse Spark, awaiting Slither re-verification."
            ),
            "remaining_checks": [],
        }

    if not result["success"]:
        return {
            "patch_verified": False,
            "patch_verification_status": "failed",
            "patch_verification_details": (
                f"Slither could not verify patch: {result['error']}"
            ),
            "remaining_checks": [],
        }

    remaining = result["detector_checks"]

    if target_checks:
        still_present = [c for c in target_checks if c in remaining]
        if still_present:
            return {
                "patch_verified": False,
                "patch_verification_status": "failed",
                "patch_verification_details": (
                    "Patch still triggers Slither detectors: "
                    + ", ".join(still_present)
                ),
                "remaining_checks": remaining,
            }
        return {
            "patch_verified": True,
            "patch_verification_status": "verified",
            "patch_verification_details": (
                "Slither re-analysis confirms target vulnerability is no longer detected."
            ),
            "remaining_checks": remaining,
        }

    high_medium = [
        d["check"]
        for d in result["detectors"]
        if d.get("impact") in ("High", "Medium", "Critical") and d.get("check")
    ]
    if high_medium:
        return {
            "patch_verified": False,
            "patch_verification_status": "failed",
            "patch_verification_details": (
                "Patch still has High/Medium Slither findings: "
                + ", ".join(sorted(set(high_medium)))
            ),
            "remaining_checks": remaining,
        }

    return {
        "patch_verified": True,
        "patch_verification_status": "verified",
        "patch_verification_details": (
            "Slither re-analysis found no High/Medium vulnerabilities in patched code."
        ),
        "remaining_checks": remaining,
    }


if __name__ == "__main__":
    print(f"Slither available: {is_slither_available()}")
    demo = '''
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract Bank {
    mapping(address => uint256) public balances;
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
'''
    print(json.dumps(run_slither(demo, "Bank.sol"), indent=2, default=str))

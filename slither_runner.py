"""SentryVision - Slither Runner

F1: Deterministic static analysis
Also used for F3 verified patches (re-scan proposed fixes).
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

SLITHER_TIMEOUT = int(os.getenv("SLITHER_TIMEOUT_SECONDS", "90"))
ENABLE_SLITHER = os.getenv("ENABLE_SLITHER", "true").strip().lower() in {
    "1", "true", "yes", "on",
}
DEFAULT_SOLC = os.getenv("SOLC_VERSION", "0.8.20")

KEEP_IMPACTS = {"High", "Medium", "Critical"}

PRIORITY_CHECKS = {
    "reentrancy-eth", "reentrancy-no-eth", "reentrancy-benign", "reentrancy-events",
    "reentrancy-unlimited-gas", "controlled-delegatecall", "delegatecall-loop",
    "unchecked-lowlevel", "unchecked-send", "arbitrary-send-eth", "arbitrary-send-erc20",
    "suicidal", "tx-origin", "unprotected-upgrade", "locked-ether", "void-cst", "rtlo",
    "shadowing-state", "uninitialized-state", "uninitialized-storage", "uninitialized-local",
    "arbitrary-send", "controlled-array-length", "msg-value-loop",
}

DROP_CHECKS = {
    "naming-convention", "solc-version", "pragma", "external-function", "low-level-calls",
    "too-many-digits", "constable-states", "immutable-states", "var-read-using-this",
    "dead-code", "unused-state", "unused-return", "similar-names",
}


def is_slither_available() -> bool:
    if not ENABLE_SLITHER:
        return False
    try:
        result = subprocess.run(["slither", "--version"], capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except Exception:
        return False


def slither_available() -> bool:
    return is_slither_available()


def _safe_filename(contract_name: str) -> str:
    name = Path(contract_name or "Contract.sol").name
    name = re.sub(r"[^a-zA-Z0-9_.-]", "_", name)
    return name if name.endswith(".sol") else f"{name}.sol"


def _normalize_pragma(source_code: str, version: Optional[str] = None) -> str:
    ver = version or DEFAULT_SOLC
    pinned = f"pragma solidity {ver};"
    if re.search(r"pragma\s+solidity\s+[^;]+;", source_code):
        return re.sub(r"pragma\s+solidity\s+[^;]+;", pinned, source_code, count=1)
    return pinned + "\n" + source_code


def _extract_solc_version(source_code: str) -> str:
    m = re.search(r"pragma\s+solidity\s+([^;]+);", source_code)
    if not m:
        return DEFAULT_SOLC
    spec = m.group(1).strip()
    exact = re.fullmatch(r"(\d+\.\d+\.\d+)", spec)
    if exact:
        return exact.group(1)
    if re.search(r"[\^>=~]", spec) and "0.8." in spec:
        return DEFAULT_SOLC
    nums = re.findall(r"\d+\.\d+\.\d+", spec)
    if nums:
        if any(n.startswith("0.8.") for n in nums):
            return DEFAULT_SOLC
        return nums[-1]
    nums2 = re.findall(r"\d+\.\d+", spec)
    if nums2:
        major_minor = nums2[-1]
        if major_minor.startswith("0.8"):
            return DEFAULT_SOLC
        return major_minor + ".0"
    return DEFAULT_SOLC


def _try_set_solc_version(version: str) -> str:
    candidates = []
    for v in (version, DEFAULT_SOLC, "0.8.20", "0.8.19", "0.8.17"):
        if v and v not in candidates:
            candidates.append(v)
    last_err = None
    for ver in candidates:
        try:
            proc = subprocess.run(
                ["solc-select", "use", ver, "--always-install"],
                capture_output=True, text=True, timeout=90, check=False,
            )
            check = subprocess.run(["solc", "--version"], capture_output=True, text=True, timeout=15)
            out = (check.stdout or "") + (check.stderr or "")
            if check.returncode == 0 and ver in out.replace("v", ""):
                logger.info("solc-select active: %s", ver)
                return ver
            if proc.returncode == 0 and check.returncode == 0:
                logger.info("solc-select use %s (%s)", ver, out.strip()[:80])
                return ver
            last_err = (proc.stderr or proc.stdout or out or "")[:200]
        except Exception as exc:
            last_err = str(exc)
            logger.warning("solc-select failed for %s: %s", ver, exc)
    logger.warning("Could not activate solc; last error: %s", last_err)
    return version or DEFAULT_SOLC


def _short_error(text: str, limit: int = 240) -> str:
    text = (text or "").strip()
    if not text:
        return "unknown error"
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for ln in reversed(lines):
        if any(k in ln for k in ("InvalidCompilation", "CompilerError", "ParserError", "TypeError", "DeclarationError")):
            return ln[:limit]
    return (lines[-1] if lines else text)[:limit]


def _classify_slither_error(error: Optional[str]) -> str:
    text = (error or "").lower()
    if not text:
        return "execution_error"
    if "timed out" in text or "timeout" in text:
        return "timeout"
    compile_markers = (
        "invalidcompilation", "compilererror", "compilation failed", "compile",
        "parsererror", "solc", "source file requires different compiler",
        "not found: file", "declarationerror", "typeerror", "syntax error",
    )
    if any(marker in text for marker in compile_markers):
        return "compile_failed"
    return "execution_error"


def _normalize_detectors(raw: dict) -> list:
    results = raw.get("results") or {}
    detectors = results.get("detectors") or []
    out = []
    for d in detectors:
        out.append({
            "check": d.get("check") or d.get("name") or "unknown",
            "impact": d.get("impact") or "Informational",
            "confidence": d.get("confidence") or "Medium",
            "description": d.get("description") or "",
        })
    return out


def filter_findings(detectors: list) -> list:
    filtered = []
    for d in detectors:
        check = d.get("check") or ""
        impact = d.get("impact") or ""
        if check in DROP_CHECKS:
            continue
        if impact not in KEEP_IMPACTS and check not in PRIORITY_CHECKS:
            continue
        filtered.append(d)
    return filtered


def run_slither(source_code: str, contract_name: str = "Contract.sol") -> Optional[Dict[str, Any]]:
    if not is_slither_available():
        return None
    if not source_code or not source_code.strip():
        return {
            "success": False, "detectors": [], "filtered_detectors": [], "detector_checks": [],
            "count": 0, "filtered_count": 0, "raw": None, "error": "Empty source", "error_kind": "compile_failed",
        }

    solc_ver = _extract_solc_version(source_code)
    solc_ver = _try_set_solc_version(solc_ver)
    source = _normalize_pragma(source_code, version=solc_ver)
    fname = _safe_filename(contract_name)

    with tempfile.TemporaryDirectory(prefix="sv_slither_") as tmp:
        tmp_path = Path(tmp)
        sol_file = tmp_path / fname
        out_file = tmp_path / "slither.json"
        sol_file.write_text(source, encoding="utf-8")

        try:
            proc = subprocess.run(
                ["slither", str(sol_file), "--json", str(out_file)],
                capture_output=True, text=True, timeout=SLITHER_TIMEOUT, cwd=str(tmp_path),
            )
        except subprocess.TimeoutExpired:
            return {
                "success": False, "detectors": [], "filtered_detectors": [], "detector_checks": [],
                "count": 0, "filtered_count": 0, "raw": None,
                "error": f"Slither timed out after {SLITHER_TIMEOUT}s", "error_kind": "timeout",
            }
        except Exception as exc:
            err = str(exc)
            return {
                "success": False, "detectors": [], "filtered_detectors": [], "detector_checks": [],
                "count": 0, "filtered_count": 0, "raw": None,
                "error": err, "error_kind": _classify_slither_error(err),
            }

        if not out_file.exists():
            raw_err = proc.stderr or proc.stdout or "Slither produced no JSON output"
            err = _short_error(raw_err)
            return {
                "success": False, "detectors": [], "filtered_detectors": [], "detector_checks": [],
                "count": 0, "filtered_count": 0, "raw": None,
                "error": err, "error_kind": _classify_slither_error(err),
            }

        try:
            raw = json.loads(out_file.read_text(encoding="utf-8"))
        except Exception as exc:
            err = f"Invalid Slither JSON: {exc}"
            return {
                "success": False, "detectors": [], "filtered_detectors": [], "detector_checks": [],
                "count": 0, "filtered_count": 0, "raw": None,
                "error": err, "error_kind": "execution_error",
            }

        if not raw.get("success", True):
            err = _short_error(str(raw.get("error") or "Compilation failed"))
            return {
                "success": False, "detectors": [], "filtered_detectors": [], "detector_checks": [],
                "count": 0, "filtered_count": 0, "raw": raw,
                "error": err, "error_kind": _classify_slither_error(err) if err else "compile_failed",
            }

        detectors = _normalize_detectors(raw)
        filtered = filter_findings(detectors)
        return {
            "success": True,
            "detectors": detectors,
            "filtered_detectors": filtered,
            "detector_checks": sorted({d["check"] for d in detectors if d.get("check")}),
            "count": len(detectors),
            "filtered_count": len(filtered),
            "raw": raw,
            "error": None,
            "error_kind": None,
        }


def run_slither_on_code(source_code: str, contract_name: str = "Contract.sol") -> Optional[Dict[str, Any]]:
    return run_slither(source_code, contract_name)


def verify_patch(
    patched_code: str,
    target_checks: Optional[List[str]] = None,
    contract_name: str = "Patched.sol",
) -> Dict[str, Any]:
    if not patched_code or not patched_code.strip():
        return {
            "patch_verified": False,
            "patch_verification_status": "not_checked",
            "verification_error_kind": None,
            "patch_verification_details": "No patched code provided.",
            "remaining_checks": [],
        }

    result = run_slither(patched_code, contract_name)

    if result is None:
        return {
            "patch_verified": False,
            "patch_verification_status": "slither_unavailable",
            "verification_error_kind": "slither_unavailable",
            "patch_verification_details": "Patch generated by Muse Spark, awaiting Slither re-verification.",
            "remaining_checks": [],
        }

    if not result.get("success"):
        err = result.get("error") or "unknown error"
        kind = result.get("error_kind") or _classify_slither_error(err)
        return {
            "patch_verified": False,
            "patch_verification_status": "failed",
            "verification_error_kind": kind,
            "patch_verification_details": "Could not compile/verify patch with Slither: " + err,
            "remaining_checks": [],
        }

    remaining = result.get("detector_checks") or []

    if target_checks:
        still_present = [c for c in target_checks if c in remaining]
        if still_present:
            return {
                "patch_verified": False,
                "patch_verification_status": "failed",
                "verification_error_kind": None,
                "patch_verification_details": "Patch still triggers Slither detectors: " + ", ".join(still_present),
                "remaining_checks": remaining,
            }
        return {
            "patch_verified": True,
            "patch_verification_status": "verified",
            "verification_error_kind": None,
            "patch_verification_details": "Slither re-analysis confirms target vulnerability is no longer detected.",
            "remaining_checks": remaining,
        }

    high_medium = [
        d["check"]
        for d in (result.get("detectors") or [])
        if d.get("impact") in ("High", "Medium", "Critical") and d.get("check")
    ]
    if high_medium:
        return {
            "patch_verified": False,
            "patch_verification_status": "failed",
            "verification_error_kind": None,
            "patch_verification_details": "Patch still has High/Medium Slither findings: " + ", ".join(sorted(set(high_medium))),
            "remaining_checks": remaining,
        }

    return {
        "patch_verified": True,
        "patch_verification_status": "verified",
        "verification_error_kind": None,
        "patch_verification_details": "Slither re-analysis found no High/Medium vulnerabilities in patched code.",
        "remaining_checks": remaining,
    }

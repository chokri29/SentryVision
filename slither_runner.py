"""SentryVision - Slither Runner

F1: Deterministic static analysis
Also used for F3 verified patches (re-scan proposed fixes).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from semantic_version import NpmSpec, Version

from solc_util import (
    solc_artifact_path as _solc_artifact_path,
    installed_solc_versions as _installed_solc_versions,
    install_solc as _install_solc,
    extract_solc_version as _extract_solc_version,
    resolve_solc_binary as _resolve_solc_binary,
)

logger = logging.getLogger("sentryvision.slither")

SLITHER_TIMEOUT = int(os.getenv("SLITHER_TIMEOUT_SECONDS", "90"))
ENABLE_SLITHER = os.getenv("ENABLE_SLITHER", "true").strip().lower() in {"1", "true", "yes", "on"}
DEFAULT_SOLC = os.getenv("SOLC_VERSION", "0.8.20")
KEEP_IMPACTS = {"High", "Medium"}
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
        return subprocess.run(["slither", "--version"], capture_output=True, text=True, timeout=10).returncode == 0
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

_SOLC_LOCK = threading.Lock()
OZ_ROOT = Path(__file__).resolve().parent / "vendor" / "openzeppelin" / "contracts"
_OZ_PREFIXES = ("@openzeppelin/contracts/", "openzeppelin-contracts/contracts/", "lib/openzeppelin-contracts/contracts/")
SUPPORTED_OZ_IMPORTS = frozenset({
    "access/Ownable.sol", "interfaces/IERC20.sol", "security/Pausable.sol",
    "security/ReentrancyGuard.sol", "token/ERC20/ERC20.sol", "token/ERC20/IERC20.sol",
    "token/ERC20/extensions/IERC20Metadata.sol", "token/ERC20/utils/SafeERC20.sol",
    "utils/Address.sol", "utils/Context.sol", "utils/Pausable.sol", "utils/ReentrancyGuard.sol",
})
_IMPORT_RE = re.compile(r"""import\s+(?:[^'";]*?\s+from\s+)?(?P<q>["'])(?P<path>[^"']+)(?P=q)""")

def oz_relative(path: str) -> Optional[str]:
    norm = path.replace("\\", "/").lstrip("./")
    for prefix in _OZ_PREFIXES:
        if norm.startswith(prefix):
            return norm[len(prefix):]
    return None

def rewrite_known_oz_imports(source: str) -> str:
    def repl(match: re.Match) -> str:
        path = match.group("path")
        rel = oz_relative(path)
        if not rel or rel not in SUPPORTED_OZ_IMPORTS or not (OZ_ROOT / rel).is_file():
            return match.group(0)
        quote = match.group("q")
        return match.group(0).replace(f"{quote}{path}{quote}", f"{quote}./oz/{rel}{quote}", 1)
    return _IMPORT_RE.sub(repl, source)

def unsupported_imports(source: str) -> List[str]:
    found: List[str] = []
    seen = set()
    for match in _IMPORT_RE.finditer(_strip_solidity(source, keep_strings=True)):
        path = match.group("path")
        if path in seen:
            continue
        rel = oz_relative(path)
        if rel is not None and rel in SUPPORTED_OZ_IMPORTS and (OZ_ROOT / rel).is_file():
            continue
        if rel is not None or path.startswith(".") or path.startswith("@") or "/" in path or path.endswith(".sol"):
            seen.add(path)
            found.append(path)
    return found

def _slither_command(sol_file: Path, out_file: Path, solc_bin: Optional[str]) -> List[str]:
    cmd = ["slither", str(sol_file), "--json", str(out_file)]
    if solc_bin:
        cmd.extend(["--solc", solc_bin])
    return cmd

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
    compile_markers = ("invalidcompilation", "compilererror", "compilation failed", "compile", "parsererror", "solc", "source file requires different compiler", "not found: file", "declarationerror", "typeerror", "syntax error")
    if any(marker in text for marker in compile_markers):
        return "compile_failed"
    return "execution_error"

def _normalize_detectors(raw: dict) -> list:
    results = raw.get("results") or {}
    out = []
    for detector in results.get("detectors") or []:
        lines, elements = set(), []
        for element in detector.get("elements") or []:
            mapping = element.get("source_mapping") or {}
            lines.update(line for line in (mapping.get("lines") or []) if isinstance(line, int) and line > 0)
            if element.get("name"):
                elements.append(str(element["name"]))
        out.append({
            "check": detector.get("check") or detector.get("name") or "unknown",
            "impact": detector.get("impact") or "Informational",
            "confidence": detector.get("confidence") or "Medium",
            "description": detector.get("description") or "",
            "lines": sorted(lines),
            "elements": sorted(set(elements)),
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

def run_slither(source_code: str, contract_name: str = "Contract.sol", *, require_pragma: bool = False) -> Optional[Dict[str, Any]]:
    if not source_code or not source_code.strip():
        return {"success": False, "detectors": [], "filtered_detectors": [], "detector_checks": [], "count": 0, "filtered_count": 0, "raw": None, "error": "Empty source", "error_kind": "compile_failed"}
    missing = unsupported_imports(source_code)
    if missing:
        shown = ", ".join(missing[:5])
        extra = "" if len(missing) <= 5 else f" (+{len(missing) - 5} more)"
        return {"success": False, "detectors": [], "filtered_detectors": [], "detector_checks": [], "count": 0, "filtered_count": 0, "raw": None, "error": f"Unsupported import: {shown}{extra}. Result is model-only.", "error_kind": "unsupported_import", "unresolved_imports": missing}
    pragma_match = re.search(r"pragma\s+solidity\s+([^;]+);", source_code)
    if require_pragma and not pragma_match:
        return {"success": False, "detectors": [], "filtered_detectors": [], "detector_checks": [], "count": 0, "filtered_count": 0, "raw": None, "error": "unverified: no compatible compiler installed.", "error_kind": "compile_failed"}
    rewritten = rewrite_known_oz_imports(source_code)
    selected_version = _extract_solc_version(source_code)
    if not selected_version:
        return {"success": False, "detectors": [], "filtered_detectors": [], "detector_checks": [], "count": 0, "filtered_count": 0, "raw": None, "error": "unverified: no compatible compiler installed.", "error_kind": "compile_failed"}
    solc_ver, solc_bin = _resolve_solc_binary(selected_version)
    if not solc_bin:
        return {"success": False, "detectors": [], "filtered_detectors": [], "detector_checks": [], "count": 0, "filtered_count": 0, "raw": None, "error": "unverified: no compatible compiler installed.", "error_kind": "compile_failed"}
    if not is_slither_available():
        return None
    source = rewritten if require_pragma else _normalize_pragma(rewritten, version=solc_ver)
    fname = _safe_filename(contract_name)
    with tempfile.TemporaryDirectory(prefix="sv_slither_") as tmp:
        tmp_path = Path(tmp)
        if "./oz/" in source:
            shutil.copytree(OZ_ROOT, tmp_path / "oz")
        sol_file = tmp_path / fname
        out_file = tmp_path / "slither.json"
        sol_file.write_text(source, encoding="utf-8")
        try:
            proc = subprocess.run(_slither_command(sol_file, out_file, solc_bin), capture_output=True, text=True, timeout=SLITHER_TIMEOUT, cwd=str(tmp_path))
        except subprocess.TimeoutExpired:
            return {"success": False, "detectors": [], "filtered_detectors": [], "detector_checks": [], "count": 0, "filtered_count": 0, "raw": None, "error": f"Slither timed out after {SLITHER_TIMEOUT}s", "error_kind": "timeout"}
        except Exception as exc:
            err = str(exc)
            return {"success": False, "detectors": [], "filtered_detectors": [], "detector_checks": [], "count": 0, "filtered_count": 0, "raw": None, "error": err, "error_kind": _classify_slither_error(err)}
        if not out_file.exists():
            err = _short_error(proc.stderr or proc.stdout or "Slither produced no JSON output")
            return {"success": False, "detectors": [], "filtered_detectors": [], "detector_checks": [], "count": 0, "filtered_count": 0, "raw": None, "error": err, "error_kind": _classify_slither_error(err)}
        try:
            raw = json.loads(out_file.read_text(encoding="utf-8"))
        except Exception as exc:
            return {"success": False, "detectors": [], "filtered_detectors": [], "detector_checks": [], "count": 0, "filtered_count": 0, "raw": None, "error": f"Invalid Slither JSON: {exc}", "error_kind": "execution_error"}
        if not raw.get("success", True):
            err = _short_error(str(raw.get("error") or "Compilation failed"))
            return {"success": False, "detectors": [], "filtered_detectors": [], "detector_checks": [], "count": 0, "filtered_count": 0, "raw": raw, "error": err, "error_kind": _classify_slither_error(err) if err else "compile_failed"}
        detectors = _normalize_detectors(raw)
        filtered = filter_findings(detectors)
        return {"success": True, "detectors": detectors, "filtered_detectors": filtered, "detector_checks": sorted({d["check"] for d in detectors if d.get("check")}), "count": len(detectors), "filtered_count": len(filtered), "raw": raw, "error": None, "error_kind": None}

def run_slither_on_code(source_code: str, contract_name: str = "Contract.sol") -> Optional[Dict[str, Any]]:
    return run_slither(source_code, contract_name)

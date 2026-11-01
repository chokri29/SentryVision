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

def _installed_solc_versions() -> List[str]:
    root = Path(os.getenv("SOLC_SELECT_INSTALL_DIR", str(Path.home() / ".solc-select")))
    artifacts = root / "artifacts"
    versions = []
    if artifacts.is_dir():
        for item in artifacts.glob("solc-*"):
            version = item.name.removeprefix("solc-")
            if re.fullmatch(r"\d+\.\d+\.\d+", version) and _solc_artifact_path(version):
                versions.append(version)
    return sorted(set(versions), key=Version)


def _extract_solc_version(source_code: str) -> Optional[str]:
    match = re.search(r"pragma\s+solidity\s+([^;]+);", source_code)
    spec = match.group(1).strip() if match else DEFAULT_SOLC
    try:
        constraint = NpmSpec(spec)
    except ValueError:
        logger.warning("Unsupported Solidity pragma constraint: %s", spec)
        return None
    matches = [v for v in _installed_solc_versions() if constraint.match(Version(v))]
    if matches:
        return sorted(matches, key=Version)[-1]
    if re.fullmatch(r"\d+\.\d+\.\d+", spec):
        return spec if _install_solc(spec) else None
    return None

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

def _solc_artifact_path(version: str) -> Optional[Path]:
    roots: List[Path] = []
    env_root = os.getenv("SOLC_SELECT_INSTALL_DIR")
    if env_root:
        roots.append(Path(env_root))
    home_root = Path.home() / ".solc-select"
    if home_root not in roots:
        roots.append(home_root)
    for root in roots:
        candidate = root / "artifacts" / f"solc-{version}" / f"solc-{version}"
        if candidate.is_file():
            return candidate
    return None

def _install_solc(version: str) -> Optional[Path]:
    existing = _solc_artifact_path(version)
    if existing:
        return existing
    with _SOLC_LOCK:
        existing = _solc_artifact_path(version)
        if existing:
            return existing
        try:
            proc = subprocess.run(["solc-select", "install", version], capture_output=True, text=True, timeout=90, check=False)
        except Exception as exc:
            logger.warning("solc-select install %s failed: %s", version, exc)
            return None
        path = _solc_artifact_path(version)
        if path:
            return path
        return None

def _resolve_solc_binary(version: Optional[str]):
    if not version:
        return None, None
    path = _solc_artifact_path(version) or _install_solc(version)
    return (version, str(path)) if path else (version, None)

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

def _strip_solidity(source: str, keep_strings: bool = False) -> str:
    out: List[str] = []
    i = 0
    n = len(source)
    while i < n:
        if source.startswith("//", i):
            j = source.find("\n", i)
            i = n if j < 0 else j
            continue
        if source.startswith("/*", i):
            j = source.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if source[i] in "\"'":
            quote = source[i]
            start = i
            i += 1
            while i < n:
                if source[i] == "\\":
                    i += 2
                    continue
                if source[i] == quote:
                    i += 1
                    break
                i += 1
            out.append(source[start:i] if keep_strings else " ")
            continue
        out.append(source[i])
        i += 1
    return "".join(out)

def _match_brace(source: str, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1

def _match_paren(source: str, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(source)):
        if source[i] == "(":
            depth += 1
        elif source[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1

def _blank_assembly(body: str) -> str:
    chars = list(body)
    for match in re.finditer(r"\bassembly\b", body):
        brace = body.find("{", match.end())
        if brace < 0:
            continue
        end = _match_brace(body, brace)
        if end < 0:
            continue
        for i in range(match.start(), end + 1):
            if chars[i] != "\n":
                chars[i] = " "
    return "".join(chars)

def _header_after_params(body: str, paren_open: int):
    close = _match_paren(body, paren_open)
    if close < 0:
        return "", ""
    depth = 0
    for i in range(close + 1, len(body)):
        char = body[i]
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif depth == 0 and char in "{;":
            return body[close + 1:i], ("body" if char == "{" else "decl")
    return "", ""

def _is_public_header(header: str) -> bool:
    match = re.search(r"\b(public|external|internal|private)\b", header)
    return bool(match and match.group(1) in {"public", "external"})

def _normalize_param_type(raw: str) -> str:
    t = " ".join((raw or "").split())
    if not t:
        return "unknown"
    t = t.replace(" memory", "").replace(" calldata", "").replace(" storage", "").replace(" indexed", "")
    return t.strip()

def _param_types_from_list(params_src: str) -> List[str]:
    if not params_src or not params_src.strip():
        return []
    types: List[str] = []
    depth = 0
    current: List[str] = []
    for ch in params_src:
        if ch in "(<[":
            depth += 1
            current.append(ch)
        elif ch in ")>]":
            depth = max(0, depth - 1)
            current.append(ch)
        elif ch == "," and depth == 0:
            part = "".join(current).strip()
            if part:
                tokens = part.split()
                if len(tokens) >= 2 and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", tokens[-1]):
                    type_part = " ".join(tokens[:-1])
                else:
                    type_part = part
                types.append(_normalize_param_type(type_part))
            current = []
        else:
            current.append(ch)
    part = "".join(current).strip()
    if part:
        tokens = part.split()
        if len(tokens) >= 2 and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", tokens[-1]):
            type_part = " ".join(tokens[:-1])
        else:
            type_part = part
        types.append(_normalize_param_type(type_part))
    return types

def _params_inside(body: str, open_paren_index: int) -> str:
    if open_paren_index < 0 or open_paren_index >= len(body) or body[open_paren_index] != "(":
        return ""
    depth = 0
    for i in range(open_paren_index, len(body)):
        ch = body[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return body[open_paren_index + 1:i]
    return ""

def public_entry_points(source_code: str) -> List[str]:
    """Public/external entry signatures: name(type,…), plus receive/fallback."""
    if not source_code or not source_code.strip():
        return []
    cleaned = _strip_solidity(source_code)
    sigs: set[str] = set()
    for match in re.finditer(r"\b(contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)\b", cleaned):
        if match.group(1) == "interface":
            continue
        brace = cleaned.find("{", match.end())
        if brace < 0:
            continue
        end = _match_brace(cleaned, brace)
        if end < 0:
            continue
        body = _blank_assembly(cleaned[brace + 1:end])
        for func in re.finditer(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", body):
            name = func.group(1)
            open_paren = func.end() - 1
            header, kind = _header_after_params(body, open_paren)
            if kind == "body" and _is_public_header(header):
                types = _param_types_from_list(_params_inside(body, open_paren))
                sigs.add(f"{name}({','.join(types)})")
        for keyword in ("receive", "fallback"):
            for special in re.finditer(rf"\b{keyword}\s*\(", body):
                open_paren = special.end() - 1
                header, kind = _header_after_params(body, open_paren)
                if kind == "body" and _is_public_header(header):
                    sigs.add(f"{keyword}()")
    return sorted(sigs)

def surface_gap(original_code: str, patched_code: str) -> List[str]:
    original = public_entry_points(original_code)
    if not original:
        return []
    patched = set(public_entry_points(patched_code))
    return sorted(set(original) - patched)

def _public_entry_bodies(source_code: str) -> Dict[str, List[str]]:
    """Conservatively map public/external entry signatures to source bodies."""
    if not source_code or not source_code.strip():
        return {}
    cleaned = _strip_solidity(source_code)
    found: Dict[str, List[str]] = {}
    for contract in re.finditer(r"\b(contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)\b", cleaned):
        if contract.group(1) == "interface":
            continue
        brace = cleaned.find("{", contract.end())
        if brace < 0:
            continue
        contract_end = _match_brace(cleaned, brace)
        if contract_end < 0:
            continue
        body = _blank_assembly(cleaned[brace + 1:contract_end])
        entries = list(re.finditer(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", body))
        entries += [m for keyword in ("receive", "fallback") for m in re.finditer(rf"\b{keyword}\s*\(", body)]
        for entry in entries:
            name = entry.group(1) if entry.lastindex else entry.group(0).split("(")[0].strip()
            open_paren = entry.end() - 1
            header, kind = _header_after_params(body, open_paren)
            if kind != "body" or not _is_public_header(header):
                continue
            close_paren = _match_paren(body, open_paren)
            if close_paren < 0:
                continue
            open_brace = close_paren + 1 + len(header)
            if open_brace >= len(body) or body[open_brace] != "{":
                continue
            close_brace = _match_brace(body, open_brace)
            if close_brace < 0:
                continue
            signature = f"{name}()" if name in {"receive", "fallback"} else f"{name}({','.join(_param_types_from_list(_params_inside(body, open_paren)))})"
            found.setdefault(signature, []).append(body[open_brace + 1:close_brace])
    return found


def _is_gutted_body(body: str) -> bool:
    """Recognize only clear empty/always-reverting bodies; ambiguity fails open."""
    cleaned = _strip_solidity(body).strip()
    if not cleaned:
        return True
    if re.fullmatch(r"revert(?:\s*\([^;]*\))?\s*;?", cleaned):
        return True
    if re.fullmatch(r"require\s*\(\s*false\s*(?:,\s*.*?)?\s*\)\s*;?", cleaned):
        return True
    return False


def gutted_entry_points(original_code: Optional[str], patched_code: str) -> List[str]:
    """Find preserved entry points changed from useful bodies to clear stubs."""
    if not original_code:
        return []
    original = _public_entry_bodies(original_code)
    patched = _public_entry_bodies(patched_code)
    gutted: List[str] = []
    for signature in sorted(set(original) & set(patched)):
        old_bodies, new_bodies = original[signature], patched[signature]
        # Ambiguous duplicate extraction is deliberately not treated as evidence.
        if len(old_bodies) != len(new_bodies):
            continue
        for old_body, new_body in zip(old_bodies, new_bodies):
            if not _is_gutted_body(old_body) and _is_gutted_body(new_body):
                gutted.append(signature)
                break
    return gutted

def high_medium_check_names(detectors: list) -> List[str]:
    """Return the unique High/Medium detector IDs from a Slither result."""
    return sorted({d["check"] for d in detectors if d.get("impact") in KEEP_IMPACTS and d.get("check")})


def verify_patch(
    patched_code: str,
    target_checks: Optional[List[str]] = None,
    contract_name: str = "Patched.sol",
    original_entry_points: Optional[List[str]] = None,
    original_code: Optional[str] = None,
) -> Dict[str, Any]:
    base = {
        "patch_verified": False, "patch_verification_status": "not_checked",
        "verification_error_kind": None, "patch_verification_details": "",
        "remaining_checks": [], "surface_removed": [], "behaviour_lite_passed": False,
        "gutted_functions": [], "unresolved_imports": [],
    }
    if not patched_code or not patched_code.strip():
        base["patch_verification_details"] = "No patched code provided."
        return base
    if not original_code or not original_code.strip():
        base.update({"patch_verification_status": "failed", "verification_error_kind": "baseline_unavailable", "patch_verification_details": "Original contract unavailable; detector and public/external interface baselines cannot be verified."})
        return base
    if original_entry_points is None:
        original_entry_points = public_entry_points(original_code)
    if target_checks is None:
        baseline = run_slither(original_code, contract_name, require_pragma=True)
        if baseline is None:
            base.update({"patch_verification_status": "slither_unavailable", "verification_error_kind": "slither_unavailable", "patch_verification_details": "Slither unavailable; original detector baseline could not be established. Patch is not verified."})
            return base
        if not baseline.get("success"):
            reason = baseline.get("error") or "Slither baseline analysis unavailable."
            details = reason if reason == "unverified: no compatible compiler installed." else "Original detector baseline unavailable; patch is not verified: " + str(reason)[:180]
            error_kind = "compile_failed" if reason == "unverified: no compatible compiler installed." else baseline.get("error_kind") or "baseline_unavailable"
            base.update({"patch_verification_status": "failed", "verification_error_kind": error_kind, "patch_verification_details": details})
            return base
        target_checks = list(baseline.get("detector_checks") or [])
    result = run_slither(patched_code, contract_name, require_pragma=True)
    if result is None:
        base.update({"patch_verification_status": "slither_unavailable", "verification_error_kind": "slither_unavailable", "patch_verification_details": "Patch generated by Muse Spark, awaiting Slither re-verification."})
        return base
    if not result.get("success"):
        err = result.get("error") or "unknown error"
        kind = result.get("error_kind") or _classify_slither_error(err)
        unresolved = list(result.get("unresolved_imports") or [])
        model_only = kind == "unsupported_import"
        base.update({
            "patch_verification_status": "model_only" if model_only else "failed",
            "verification_error_kind": kind,
            "patch_verification_details": ("Model-only result — not verified. Unresolved imports: " + ", ".join(unresolved)) if model_only else (err if err == "unverified: no compatible compiler installed." else "Could not compile/verify patch with Slither: " + err),
            "unresolved_imports": unresolved,
        })
        return base
    high_medium = high_medium_check_names(result.get("detectors") or [])
    critical_high_medium = sorted({d["check"] for d in (result.get("detectors") or []) if d.get("impact") in {"Critical", "High", "Medium"} and d.get("check")})
    detected_checks = set(result.get("detector_checks") or [])
    still_present = sorted(set(target_checks or []) & detected_checks)
    missing: List[str] = sorted(set(original_entry_points or []) - set(public_entry_points(patched_code)))
    gutted = gutted_entry_points(original_code, patched_code)
    remaining = sorted(set(critical_high_medium) | set(still_present))
    base.update({"remaining_checks": remaining, "surface_removed": missing, "gutted_functions": gutted, "behaviour_lite_passed": not gutted})
    if still_present:
        base.update({"patch_verification_status": "failed", "patch_verification_details": "Original Slither detector IDs remain: " + ", ".join(still_present) + "."})
        return base
    if critical_high_medium:
        base.update({"patch_verification_status": "failed", "patch_verification_details": "Patch introduces or retains Critical/High/Medium Slither findings: " + ", ".join(critical_high_medium) + "."})
        return base
    if missing:
        base.update({"patch_verification_status": "failed", "patch_verification_details": "Slither re-scan is clean, but original public/external functions were removed: " + ", ".join(missing) + ". Deleting an entry point is not a fix."})
        return base
    if gutted:
        base.update({"patch_verification_status": "failed", "patch_verification_details": "Slither re-scan is clean, but preserved public/external entry points were gutted: " + ", ".join(gutted) + "."})
        return base
    base.update({
        "patch_verified": True, "patch_verification_status": "verified", "behaviour_lite_passed": True,
        "patch_verification_details": "Slither re-scan found no High/Medium issues; name + parameter types surface is preserved; behaviour-lite check passed.",
    })
    return base

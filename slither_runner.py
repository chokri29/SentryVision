"""SentryVision - Slither Runner (F1 + F3)."""
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
    "suicidal", "tx-origin", "unprotected-upgrade", "locked-ether",
}
DROP_CHECKS = {
    "naming-convention", "solc-version", "pragma", "external-function", "low-level-calls",
    "too-many-digits", "constable-states", "immutable-states", "var-read-using-this",
    "dead-code", "unused-state", "unused-return", "similar-names",
}
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


def _solc_artifact_path(version: str) -> Optional[Path]:
    roots: List[Path] = []
    env_root = os.getenv("SOLC_SELECT_INSTALL_DIR")
    if env_root:
        roots.append(Path(env_root))
    home_root = Path.home() / ".solc-select"
    if home_root not in roots:
        roots.append(home_root)
    cands: List[Path] = []
    for root in roots:
        art = root / "artifacts"
        cands += [
            art / f"solc-{version}",
            art / f"solc-{version}" / f"solc-{version}",
            art / f"solc-{version}" / "solc",
        ]
    for c in cands:
        try:
            if c.is_file() and c.stat().st_size > 0:
                return c
        except OSError:
            continue
    return None


def _installed_solc_versions() -> List[str]:
    versions: List[str] = []
    roots: List[Path] = []
    env_root = os.getenv("SOLC_SELECT_INSTALL_DIR")
    if env_root:
        roots.append(Path(env_root))
    roots.append(Path.home() / ".solc-select")
    for root in roots:
        art = root / "artifacts"
        if not art.is_dir():
            continue
        for item in art.glob("solc-*"):
            version = item.name.removeprefix("solc-")
            if re.fullmatch(r"\d+\.\d+\.\d+", version) and _solc_artifact_path(version):
                versions.append(version)
    return sorted(set(versions), key=Version)


def _install_solc(version: str) -> Optional[Path]:
    existing = _solc_artifact_path(version)
    if existing:
        return existing
    with _SOLC_LOCK:
        existing = _solc_artifact_path(version)
        if existing:
            return existing
        try:
            subprocess.run(["solc-select", "install", version], capture_output=True, text=True, timeout=120, check=False)
        except Exception as exc:
            logger.warning("solc-select install %s failed: %s", version, exc)
            return None
        return _solc_artifact_path(version)


def _extract_solc_version(source_code: str) -> Optional[str]:
    match = re.search(r"pragma\s+solidity\s+([^;]+);", source_code)
    spec = match.group(1).strip() if match else DEFAULT_SOLC
    try:
        constraint = NpmSpec(spec)
    except ValueError:
        logger.warning("Unsupported Solidity pragma: %s", spec)
        return None
    matches = [v for v in _installed_solc_versions() if constraint.match(Version(v))]
    if matches:
        return sorted(matches, key=Version)[-1]
    if re.fullmatch(r"\d+\.\d+\.\d+", spec):
        return spec if _install_solc(spec) else None
    for cand in ("0.8.26", "0.8.24", "0.8.20", "0.8.19", "0.8.17", "0.8.16", "0.8.13", "0.8.10", "0.8.7", "0.8.4", "0.8.0"):
        try:
            if constraint.match(Version(cand)) and _install_solc(cand):
                return cand
        except Exception:
            continue
    try:
        if constraint.match(Version(DEFAULT_SOLC)) and _install_solc(DEFAULT_SOLC):
            return DEFAULT_SOLC
    except Exception:
        pass
    # If PATH has solc, still return DEFAULT so resolve can use which(solc)
    if shutil.which("solc"):
        return DEFAULT_SOLC
    return None


def _resolve_solc_binary(version: Optional[str]):
    if not version:
        return None, None
    path = _solc_artifact_path(version) or _install_solc(version)
    if path:
        return version, str(path)
    which = shutil.which("solc")
    if which:
        logger.warning("Using PATH solc at %s (requested %s)", which, version)
        return version, which
    return version, None


def list_solc_versions() -> List[str]:
    """Installed solc versions visible to F1/F3 (for /health)."""
    versions = list(_installed_solc_versions())
    which = shutil.which("solc")
    if which and not versions:
        try:
            proc = subprocess.run([which, "--version"], capture_output=True, text=True, timeout=10)
            text = (proc.stdout or "") + (proc.stderr or "")
            m = re.search(r"(\d+\.\d+\.\d+)", text)
            if m:
                versions.append(m.group(1) + " (PATH)")
            else:
                versions.append("PATH:" + which)
        except Exception:
            versions.append("PATH:" + which)
    return versions


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


def _strip_solidity(source: str, keep_strings: bool = False) -> str:
    out: List[str] = []
    i, n = 0, len(source)
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
            quote, start = source[i], i
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


def unsupported_imports(source: str) -> List[str]:
    found, seen = [], set()
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
    if any(m in text for m in ("invalidcompilation", "compilererror", "compilation failed", "compile", "parsererror", "solc")):
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


def public_entry_points(source_code: str) -> List[str]:
    """Return public/external function signatures (name + param types)."""
    cleaned = _strip_solidity(source_code)
    sigs = []
    for m in re.finditer(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)", cleaned):
        name, params = m.group(1), m.group(2)
        header_end = cleaned.find("{", m.end())
        header = cleaned[m.end():header_end if header_end > 0 else m.end() + 80]
        if not re.search(r"\b(public|external)\b", header):
            continue
        types = []
        for part in params.split(",") if params.strip() else []:
            tokens = part.strip().split()
            if not tokens:
                continue
            if len(tokens) >= 2 and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", tokens[-1]):
                types.append(" ".join(tokens[:-1]).replace(" memory", "").replace(" calldata", "").strip())
            else:
                types.append(" ".join(tokens).strip())
        sigs.append(f"{name}({','.join(types)})")
    if re.search(r"\breceive\s*\(", cleaned):
        sigs.append("receive()")
    if re.search(r"\bfallback\s*\(", cleaned):
        sigs.append("fallback()")
    return sorted(set(sigs))


def verify_patch(
    patched_code: str,
    target_checks=None,
    contract_name: str = "Patched.sol",
    original_entry_points=None,
    original_code=None,
) -> Dict[str, Any]:
    """F3: re-run Slither on the proposed patch and check surface preservation."""
    base = {
        "patch_verified": False,
        "patch_verification_status": "not_checked",
        "verification_error_kind": None,
        "patch_verification_details": "",
        "remaining_checks": [],
        "surface_removed": [],
        "behaviour_lite_passed": False,
    }
    if not patched_code or not patched_code.strip():
        base.update(patch_verification_status="failed", verification_error_kind="compile_failed",
                    patch_verification_details="Empty patch.")
        return base
    if original_entry_points is None and original_code:
        original_entry_points = public_entry_points(original_code)
    result = run_slither(patched_code, contract_name)
    if result is None:
        base.update(patch_verification_status="slither_unavailable", verification_error_kind="slither_unavailable",
                    patch_verification_details="Slither unavailable for verification.")
        return base
    if not result.get("success"):
        base.update(patch_verification_status="failed",
                    verification_error_kind=result.get("error_kind") or "compile_failed",
                    patch_verification_details=result.get("error") or "Patch failed to compile.")
        return base
    remaining = sorted({d.get("check") for d in (result.get("filtered_detectors") or []) if d.get("check")})
    if target_checks:
        remaining = sorted(set(remaining) & set(target_checks))
    surface_removed = []
    if original_entry_points:
        patched_eps = set(public_entry_points(patched_code))
        surface_removed = sorted(set(original_entry_points) - patched_eps)
    if surface_removed:
        base.update(patch_verification_status="failed", verification_error_kind="surface_removed",
                    patch_verification_details=f"Removed public entry points: {', '.join(surface_removed[:8])}",
                    remaining_checks=remaining, surface_removed=surface_removed)
        return base
    if remaining:
        base.update(patch_verification_status="failed", verification_error_kind="still_vulnerable",
                    patch_verification_details=f"Still reports: {', '.join(remaining[:12])}",
                    remaining_checks=remaining)
        return base
    base.update(
        patch_verified=True,
        patch_verification_status="verified",
        behaviour_lite_passed=True,
        patch_verification_details="Passed Sli ther re-scan + surface check.",
    )
    return base

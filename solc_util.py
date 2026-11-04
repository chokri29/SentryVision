"""Solc binary resolution helpers for SentryVision F1/F3.

Handles both solc-select artifact layouts (Docker image) and a plain
`solc` on PATH (Render native / venv installs).
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from semantic_version import NpmSpec, Version

logger = logging.getLogger("sentryvision.slither")

_SOLC_LOCK = threading.Lock()
_PREFERRED_SOLC = (
    "0.8.38", "0.8.30", "0.8.28", "0.8.26", "0.8.24", "0.8.20",
    "0.8.19", "0.8.17", "0.8.16", "0.8.13", "0.8.10", "0.8.7", "0.8.4", "0.8.0",
)


def _env_default_solc() -> str:
    """Pick a default solc that actually exists when possible."""
    requested = (os.getenv("SOLC_VERSION") or "").strip()
    # Prefer explicit env only as a hint — still validated later
    return requested or "0.8.38"


DEFAULT_SOLC = _env_default_solc()

_PATH_SOLC_CACHE: Optional[Tuple[Optional[str], Optional[Path]]] = None


def _solc_roots() -> List[Path]:
    roots: List[Path] = []
    seen = set()

    def add(p: Path) -> None:
        try:
            key = str(p.resolve()) if p.exists() else str(p)
        except OSError:
            key = str(p)
        if key not in seen:
            seen.add(key)
            roots.append(p)

    env_root = os.getenv("SOLC_SELECT_INSTALL_DIR")
    if env_root:
        add(Path(env_root))
    add(Path.home() / ".solc-select")
    add(Path("/home/appuser/.solc-select"))
    add(Path("/opt/render/.solc-select"))
    add(Path("/usr/local/lib/solc-select"))
    add(Path("/opt/solc-select"))
    return roots


def _which(name: str) -> Optional[str]:
    try:
        proc = subprocess.run(["which", name], capture_output=True, text=True, timeout=5)
        path = (proc.stdout or "").strip()
        return path or None
    except Exception:
        return None


def _parse_solc_version_output(text: str) -> Optional[str]:
    if not text:
        return None
    m = re.search(r"Version:\s*(\d+\.\d+\.\d+)", text)
    if m:
        return m.group(1)
    m = re.search(r"\b(\d+\.\d+\.\d+)\+commit", text)
    if m:
        return m.group(1)
    m = re.search(r"\b(\d+\.\d+\.\d+)\b", text)
    return m.group(1) if m else None


def path_solc_info() -> Tuple[Optional[str], Optional[Path]]:
    """Return (version, path) for the first usable `solc` on PATH."""
    global _PATH_SOLC_CACHE
    if _PATH_SOLC_CACHE is not None:
        return _PATH_SOLC_CACHE

    path_str = _which("solc")
    if not path_str:
        _PATH_SOLC_CACHE = (None, None)
        return _PATH_SOLC_CACHE

    path = Path(path_str)
    try:
        if not (path.is_file() and os.access(path, os.X_OK)):
            _PATH_SOLC_CACHE = (None, None)
            return _PATH_SOLC_CACHE
    except OSError:
        _PATH_SOLC_CACHE = (None, None)
        return _PATH_SOLC_CACHE

    version = None
    try:
        proc = subprocess.run(
            [str(path), "--version"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        version = _parse_solc_version_output((proc.stdout or "") + "\n" + (proc.stderr or ""))
    except Exception as exc:
        logger.warning("Could not run PATH solc --version: %s", exc)

    _PATH_SOLC_CACHE = (version, path)
    return _PATH_SOLC_CACHE


def solc_artifact_path(version: str) -> Optional[Path]:
    candidates: List[Path] = []
    for root in _solc_roots():
        art = root / "artifacts"
        candidates.append(art / f"solc-{version}")
        candidates.append(art / f"solc-{version}" / f"solc-{version}")
        candidates.append(art / f"solc-{version}" / "solc")

    which_ver = _which(f"solc-{version}")
    if which_ver:
        candidates.append(Path(which_ver))

    for candidate in candidates:
        try:
            if candidate.is_file() and candidate.stat().st_size > 0 and os.access(candidate, os.X_OK):
                return candidate
        except OSError:
            continue

    path_ver, path_bin = path_solc_info()
    if path_bin and path_ver == version:
        return path_bin

    return None


def solc_select_installed_versions() -> List[str]:
    """Ask solc-select which versions it has (e.g. 0.8.38 on Render)."""
    versions: List[str] = []
    try:
        proc = subprocess.run(
            ["solc-select", "versions"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        text = (proc.stdout or "") + "\n" + (proc.stderr or "")
        for m in re.finditer(r"\b(\d+\.\d+\.\d+)\b", text):
            versions.append(m.group(1))
    except Exception as exc:
        logger.warning("solc-select versions failed: %s", exc)
    return sorted(set(v for v in versions if re.fullmatch(r"\d+\.\d+\.\d+", v)), key=Version)


def installed_solc_versions() -> List[str]:
    """Return only compiler versions backed by an executable binary."""
    candidates: set[str] = set()
    for root in _solc_roots():
        artifacts = root / "artifacts"
        if artifacts.is_dir():
            for item in artifacts.glob("solc-*"):
                version = item.name.removeprefix("solc-")
                if re.fullmatch(r"\\d+\\.\\d+\\.\\d+", version):
                    candidates.add(version)
    # solc-select inventory is discovery metadata, not proof of a usable binary.
    candidates.update(solc_select_installed_versions())
    path_version, path_binary = path_solc_info()
    if path_binary and path_version and re.fullmatch(r"\\d+\\.\\d+\\.\\d+", path_version):
        candidates.add(path_version)
    verified = [version for version in candidates if solc_artifact_path(version)]
    return sorted(set(verified), key=Version)


def install_solc(version: str) -> Optional[Path]:
    existing = solc_artifact_path(version)
    if existing:
        return existing

    path_ver, path_bin = path_solc_info()
    if path_bin and path_ver == version:
        return path_bin

    with _SOLC_LOCK:
        existing = solc_artifact_path(version)
        if existing:
            return existing
        env = os.environ.copy()
        if os.getenv("SOLC_SELECT_INSTALL_DIR"):
            env["SOLC_SELECT_INSTALL_DIR"] = os.environ["SOLC_SELECT_INSTALL_DIR"]
        try:
            proc = subprocess.run(
                ["solc-select", "install", version],
                capture_output=True, text=True, timeout=120, check=False, env=env,
            )
        except Exception as exc:
            logger.warning("solc-select install %s failed: %s", version, exc)
            return None
        global _PATH_SOLC_CACHE
        _PATH_SOLC_CACHE = None
        path = solc_artifact_path(version)
        if path:
            return path
        logger.warning(
            "solc-select install %s produced no usable binary (rc=%s) stderr=%s",
            version, proc.returncode, (proc.stderr or proc.stdout or "")[:300],
        )
        return None


def extract_solc_version(source_code: str, *, require_pragma: bool = False) -> Optional[str]:
    """Choose the highest verified installed compiler compatible with the pragma."""
    match = re.search(r"pragma\\s+solidity\\s+([^;]+);", source_code)
    if require_pragma and not match:
        return None
    available = installed_solc_versions()
    if not available:
        return None
    if match:
        spec = match.group(1).strip()
        try:
            constraint = NpmSpec(spec)
            compatible = [v for v in available if constraint.match(Version(v))]
            if compatible:
                return sorted(compatible, key=Version)[-1]
            logger.warning("No installed solc satisfies pragma %s; using highest installed %s for compile diagnostics", spec, available[-1])
        except ValueError:
            logger.warning("Unsupported Solidity pragma %s; using highest installed compiler", spec)
    # No pragma / unsupported pragma / no compatible compiler: never return
    # DEFAULT_SOLC blindly. The caller pins its temporary source to this binary.
    return available[-1]


def resolve_solc_binary(version: Optional[str]):
    """Resolve only a verified compiler; never return a requested missing version."""
    if version:
        path = solc_artifact_path(version)
        if path:
            return version, str(path)
        try:
            subprocess.run(["solc-select", "use", version], capture_output=True, text=True, timeout=60, check=False)
        except Exception as exc:
            logger.warning("solc-select use %s failed: %s", version, exc)
        global _PATH_SOLC_CACHE
        _PATH_SOLC_CACHE = None
        path_version, path_binary = path_solc_info()
        if path_binary and path_version == version:
            return version, str(path_binary)
        return None, None
    path_version, path_binary = path_solc_info()
    if path_binary and path_version:
        return path_version, str(path_binary)
    return None, None


def solc_status() -> Dict[str, Any]:
    path_version, path_binary = path_solc_info()
    versions = installed_solc_versions()
    select_versions = solc_select_installed_versions()
    preferred = [v for v in versions if v.startswith("0.8.")]
    effective_default = preferred[-1] if preferred else (versions[-1] if versions else None)
    default_binary = solc_artifact_path(effective_default) if effective_default else None
    if not default_binary and path_binary and path_version == effective_default:
        default_binary = path_binary
    return {
        "default_version": DEFAULT_SOLC,
        "effective_default": effective_default,
        "versions": versions,
        "version_count": len(versions),
        "solc_select_versions": select_versions,
        "default_binary_found": bool(default_binary),
        "default_binary_path": str(default_binary) if default_binary else None,
        "path_solc_version": path_version,
        "path_solc_binary": str(path_binary) if path_binary else None,
        "compilers_ready": bool(versions),
        "search_roots": [str(root) for root in _solc_roots()],
        "solc_select_install_dir": os.getenv("SOLC_SELECT_INSTALL_DIR"),
    }

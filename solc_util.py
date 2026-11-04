"""Solc binary resolution helpers for SentryVision F1/F3."""
from __future__ import annotations

import logging
import os
import re
import subprocess
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from semantic_version import NpmSpec, Version

logger = logging.getLogger("sentryvision.slither")

DEFAULT_SOLC = os.getenv("SOLC_VERSION", "0.8.20")
_SOLC_LOCK = threading.Lock()
_PREFERRED_SOLC = (
    "0.8.26", "0.8.24", "0.8.20", "0.8.19", "0.8.17", "0.8.16",
    "0.8.13", "0.8.10", "0.8.7", "0.8.4", "0.8.0",
)


def _solc_roots() -> List[Path]:
    """All directories that may hold solc-select artifacts (order: env, home, system)."""
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
    # Dockerfile installs under appuser even if the process user differs
    add(Path("/home/appuser/.solc-select"))
    add(Path("/usr/local/lib/solc-select"))
    add(Path("/opt/solc-select"))
    return roots


def solc_artifact_path(version: str) -> Optional[Path]:
    """Locate a solc binary for *version* across known solc-select layouts."""
    candidates: List[Path] = []
    for root in _solc_roots():
        art = root / "artifacts"
        candidates.append(art / f"solc-{version}")
        candidates.append(art / f"solc-{version}" / f"solc-{version}")
        candidates.append(art / f"solc-{version}" / "solc")
    # PATH fallback (solc-select use may put a symlink on PATH)
    for name in (f"solc-{version}", "solc"):
        which = _which(name)
        if which:
            candidates.append(Path(which))
    for candidate in candidates:
        try:
            if candidate.is_file() and candidate.stat().st_size > 0 and os.access(candidate, os.X_OK):
                return candidate
        except OSError:
            continue
    return None


def _which(name: str) -> Optional[str]:
    try:
        proc = subprocess.run(["which", name], capture_output=True, text=True, timeout=5)
        path = (proc.stdout or "").strip()
        return path or None
    except Exception:
        return None


def installed_solc_versions() -> List[str]:
    versions: List[str] = []
    for root in _solc_roots():
        artifacts = root / "artifacts"
        if not artifacts.is_dir():
            continue
        for item in artifacts.glob("solc-*"):
            version = item.name.removeprefix("solc-")
            if re.fullmatch(r"\d+\.\d+\.\d+", version) and solc_artifact_path(version):
                versions.append(version)
    return sorted(set(versions), key=Version)


def install_solc(version: str) -> Optional[Path]:
    existing = solc_artifact_path(version)
    if existing:
        return existing
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
        path = solc_artifact_path(version)
        if path:
            return path
        logger.warning(
            "solc-select install %s produced no usable binary (rc=%s) stderr=%s",
            version, proc.returncode, (proc.stderr or proc.stdout or "")[:300],
        )
        return None


def extract_solc_version(source_code: str, *, require_pragma: bool = False) -> Optional[str]:
    match = re.search(r"pragma\s+solidity\s+([^;]+);", source_code)
    if require_pragma and not match:
        return None
    spec = match.group(1).strip() if match else DEFAULT_SOLC
    try:
        constraint = NpmSpec(spec)
    except ValueError:
        logger.warning("Unsupported Solidity pragma constraint: %s", spec)
        return None
    matches = [v for v in installed_solc_versions() if constraint.match(Version(v))]
    if matches:
        return sorted(matches, key=Version)[-1]
    if re.fullmatch(r"\d+\.\d+\.\d+", spec):
        return spec if install_solc(spec) else None
    for candidate in _PREFERRED_SOLC:
        try:
            if constraint.match(Version(candidate)) and install_solc(candidate):
                return candidate
        except Exception:
            continue
    try:
        if constraint.match(Version(DEFAULT_SOLC)) and install_solc(DEFAULT_SOLC):
            return DEFAULT_SOLC
    except Exception:
        pass
    return None


def resolve_solc_binary(version: Optional[str]):
    if not version:
        return None, None
    path = solc_artifact_path(version) or install_solc(version)
    return (version, str(path)) if path else (version, None)


def solc_status() -> Dict[str, Any]:
    """Runtime compiler visibility for /health and diagnostics."""
    versions = installed_solc_versions()
    default_path = solc_artifact_path(DEFAULT_SOLC)
    roots = [str(r) for r in _solc_roots()]
    return {
        "default_version": DEFAULT_SOLC,
        "versions": versions,
        "version_count": len(versions),
        "default_binary_found": bool(default_path),
        "default_binary_path": str(default_path) if default_path else None,
        "compilers_ready": len(versions) > 0,
        "search_roots": roots,
        "solc_select_install_dir": os.getenv("SOLC_SELECT_INSTALL_DIR"),
    }

"""Solc binary resolution helpers for SentryVision F1/F3."""
from __future__ import annotations

import logging
import os
import re
import subprocess
import threading
from pathlib import Path
from typing import List, Optional

from semantic_version import NpmSpec, Version

logger = logging.getLogger("sentryvision.slither")

DEFAULT_SOLC = os.getenv("SOLC_VERSION", "0.8.20")
_SOLC_LOCK = threading.Lock()
_PREFERRED_SOLC = (
    "0.8.26", "0.8.24", "0.8.20", "0.8.19", "0.8.17", "0.8.16",
    "0.8.13", "0.8.10", "0.8.7", "0.8.4", "0.8.0",
)


def solc_artifact_path(version: str) -> Optional[Path]:
    """Locate a solc binary for *version* across known solc-select layouts."""
    roots: List[Path] = []
    env_root = os.getenv("SOLC_SELECT_INSTALL_DIR")
    if env_root:
        roots.append(Path(env_root))
    home_root = Path.home() / ".solc-select"
    if home_root not in roots:
        roots.append(home_root)
    for extra in (Path("/usr/local/lib/solc-select"), Path("/opt/solc-select")):
        if extra not in roots:
            roots.append(extra)
    candidates: List[Path] = []
    for root in roots:
        art = root / "artifacts"
        candidates.append(art / f"solc-{version}")
        candidates.append(art / f"solc-{version}" / f"solc-{version}")
        candidates.append(art / f"solc-{version}" / "solc")
    for candidate in candidates:
        try:
            if candidate.is_file() and candidate.stat().st_size > 0:
                return candidate
        except OSError:
            continue
    return None


def installed_solc_versions() -> List[str]:
    versions: List[str] = []
    roots: List[Path] = []
    env_root = os.getenv("SOLC_SELECT_INSTALL_DIR")
    if env_root:
        roots.append(Path(env_root))
    home_root = Path.home() / ".solc-select"
    if home_root not in roots:
        roots.append(home_root)
    for extra in (Path("/usr/local/lib/solc-select"), Path("/opt/solc-select")):
        if extra not in roots:
            roots.append(extra)
    for root in roots:
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

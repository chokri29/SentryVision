"""Monkey-patch solc path resolution at process start."""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("sentryvision.slither")

def apply() -> None:
    try:
        import slither_runner as sr
    except Exception as exc:
        logger.warning("solc_patch: cannot import slither_runner: %s", exc)
        return

    def _solc_artifact_path(version: str) -> Optional[Path]:
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
        candidates = []
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

    def _extract_solc_version(source_code: str) -> Optional[str]:
        from semantic_version import NpmSpec, Version
        match = re.search(r"pragma\s+solidity\s+([^;]+);", source_code)
        default = getattr(sr, "DEFAULT_SOLC", "0.8.20")
        spec = match.group(1).strip() if match else default
        try:
            constraint = NpmSpec(spec)
        except ValueError:
            return None
        installed = []
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
                ver = item.name.removeprefix("solc-")
                if re.fullmatch(r"\d+\.\d+\.\d+", ver) and _solc_artifact_path(ver):
                    installed.append(ver)
        matches = [v for v in installed if constraint.match(Version(v))]
        if matches:
            return sorted(matches, key=lambda v: Version(v))[-1]
        if re.fullmatch(r"\d+\.\d+\.\d+", spec):
            return spec if sr._install_solc(spec) else None
        preferred = [
            "0.8.26", "0.8.24", "0.8.20", "0.8.19", "0.8.17", "0.8.16",
            "0.8.13", "0.8.10", "0.8.7", "0.8.4", "0.8.0",
        ]
        for cand in preferred:
            try:
                if constraint.match(Version(cand)):
                    path = sr._install_solc(cand)
                    if path:
                        return cand
            except Exception:
                continue
        try:
            if constraint.match(Version(default)) and sr._install_solc(default):
                return default
        except Exception:
            pass
        return None

    sr._solc_artifact_path = _solc_artifact_path
    sr._extract_solc_version = _extract_solc_version
    logger.info("solc_patch: multi-layout artifact resolution applied")

apply()

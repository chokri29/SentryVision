"""Compatibility shim for older deployments.

Compiler discovery and selection now live exclusively in solc_util.py.
This module intentionally delegates instead of maintaining a second,
independent version-selection implementation.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("sentryvision.slither")


def apply() -> None:
    try:
        import slither_runner as runner
        from solc_util import extract_solc_version, solc_artifact_path
    except Exception as exc:
        logger.warning("solc_patch: centralized compiler helpers unavailable: %s", exc)
        return

    # Keep legacy call sites working, but route them through verified helpers.
    runner._solc_artifact_path = solc_artifact_path
    runner._extract_solc_version = lambda source_code: extract_solc_version(source_code)
    logger.info("solc_patch: delegated compiler resolution to solc_util")


apply()

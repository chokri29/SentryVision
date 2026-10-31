"""Real verify_patch integration tests. CI installs Slither and solc; local runs may skip."""

import os
import re
import shutil
from pathlib import Path

import pytest

from slither_runner import public_entry_points, verify_patch

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "01_reentrancy.sol"


@pytest.fixture
def require_solidity_toolchain():
    missing = [name for name in ("solc", "slither") if shutil.which(name) is None]
    if missing:
        message = "missing required binaries: " + ", ".join(missing)
        if os.getenv("CI", "").lower() == "true":
            pytest.fail("CI must run real Slither e2e tests; " + message)
        pytest.skip(message)


def _fixed_source() -> str:
    return FIXTURE.read_text(encoding="utf-8")


def _verify(patched: str, original: str):
    return verify_patch(
        patched,
        contract_name="01_reentrancy.sol",
        original_code=original,
        original_entry_points=public_entry_points(original),
    )


def test_cei_patch_compiles_and_passes_slither_surface_and_behaviour(require_solidity_toolchain):
    fixed = _fixed_source()
    original = (Path(__file__).resolve().parents[1] / "examples" / "01_reentrancy.sol").read_text(encoding="utf-8")
    result = _verify(fixed, original)
    assert result["patch_verified"] is True
    assert result["patch_verification_status"] == "verified"
    assert result["remaining_checks"] == []
    assert result["surface_removed"] == []
    assert result["behaviour_lite_passed"] is True
    assert result["gutted_functions"] == []


def test_deleted_withdraw_fails_with_surface_removed(require_solidity_toolchain):
    original = _fixed_source()
    patched = re.sub(
        r"\n    function withdraw\(uint256 amount\) external \{.*?\n    \}\n",
        "\n",
        original,
        count=1,
        flags=re.DOTALL,
    )
    assert "function withdraw" not in patched
    result = _verify(patched, original)
    assert result["patch_verified"] is False
    assert "withdraw(uint256)" in result["surface_removed"]


def test_unsupported_import_returns_model_only_unverified(require_solidity_toolchain):
    original = _fixed_source()
    patched = original.replace(
        "pragma solidity ^0.8.0;",
        'pragma solidity ^0.8.0;\nimport "@openzeppelin/contracts/finance/VestingWallet.sol";',
    )
    result = _verify(patched, original)
    assert result["patch_verified"] is False
    assert result["patch_verification_status"] == "model_only"
    assert "@openzeppelin/contracts/finance/VestingWallet.sol" in result["unresolved_imports"]

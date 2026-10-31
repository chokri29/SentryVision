"""Static behaviour-lite guard for obviously gutted preserved entry points."""

from pathlib import Path

import slither_runner
from slither_runner import public_entry_points, verify_patch

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "01_reentrancy.sol"
VULNERABLE = ROOT / "examples" / "01_reentrancy.sol"


def _source() -> str:
    return FIXTURE.read_text(encoding="utf-8")


def _verify(monkeypatch, original: str, patched: str):
    monkeypatch.setattr(slither_runner, "run_slither", lambda *_args, **_kwargs: {
        "success": True, "detectors": [], "detector_checks": [],
    })
    return verify_patch(
        patched,
        original_code=original,
        original_entry_points=public_entry_points(original),
    )


def test_cei_fixed_withdraw_with_real_logic_passes_behaviour_lite(monkeypatch):
    original = VULNERABLE.read_text(encoding="utf-8")
    fixed = _source()
    result = _verify(monkeypatch, original, fixed)
    assert result["behaviour_lite_passed"] is True
    assert result["gutted_functions"] == []


def test_preserved_withdraw_revert_is_rejected(monkeypatch):
    original = _source()
    patched = original.replace(
        '''        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");''',
        "        revert();",
    )
    result = _verify(monkeypatch, original, patched)
    assert result["patch_verified"] is False
    assert result["patch_verification_status"] == "failed"
    assert result["gutted_functions"] == ["withdraw(uint256)"]


def test_original_already_reverting_entry_point_is_not_flagged(monkeypatch):
    original = """
    pragma solidity ^0.8.0;
    contract C { function stop() external { revert(); } }
    """
    result = _verify(monkeypatch, original, original)
    assert result["behaviour_lite_passed"] is True
    assert result["gutted_functions"] == []


def test_empty_preserved_body_is_rejected(monkeypatch):
    original = _source()
    patched = original.replace(
        '''    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }''',
        "    function withdraw(uint256 amount) external {}",
    )
    result = _verify(monkeypatch, original, patched)
    assert result["patch_verified"] is False
    assert result["gutted_functions"] == ["withdraw(uint256)"]

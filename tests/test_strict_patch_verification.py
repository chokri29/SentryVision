"""Regression tests for fail-closed compiler and patch-verification gates."""

import slither_runner
from slither_runner import verify_patch


ORIGINAL = """
pragma solidity ^0.8.20;
contract Vault {
    function set(uint256 amount) external {}
    function set(address account) external {}
}
"""


def _slither_result(*, detectors=None, detector_checks=None):
    return {
        "success": True,
        "detectors": list(detectors or []),
        "detector_checks": list(detector_checks or []),
    }


def _verify(monkeypatch, patched, *, detectors=None, detector_checks=None, target_checks=None):
    monkeypatch.setattr(
        slither_runner,
        "run_slither",
        lambda *_args, **_kwargs: _slither_result(
            detectors=detectors,
            detector_checks=detector_checks,
        ),
    )
    return verify_patch(
        patched,
        target_checks=target_checks if target_checks is not None else [],
        original_code=ORIGINAL,
    )


def test_pragma_selects_highest_installed_compatible_compiler(monkeypatch):
    monkeypatch.setattr(
        slither_runner,
        "_installed_solc_versions",
        lambda: ["0.7.6", "0.8.19", "0.8.20"],
    )
    assert slither_runner._extract_solc_version(
        "pragma solidity ^0.8.0; contract C {}"
    ) == "0.8.20"


def test_missing_compatible_compiler_fails_closed_before_slither(monkeypatch):
    monkeypatch.setattr(slither_runner, "_extract_solc_version", lambda _source: None)

    def slither_must_not_run():
        raise AssertionError("Slither must not run without a compatible compiler")

    monkeypatch.setattr(slither_runner, "is_slither_available", slither_must_not_run)
    result = slither_runner.run_slither(ORIGINAL, require_pragma=True)

    assert result["success"] is False
    assert result["error_kind"] == "compile_failed"
    assert result["error"] == "unverified: no compatible compiler installed."


def test_patch_without_pragma_fails_closed(monkeypatch):
    def slither_must_not_run():
        raise AssertionError("Slither must not run without a declared patch pragma")

    monkeypatch.setattr(slither_runner, "is_slither_available", slither_must_not_run)
    result = slither_runner.run_slither(
        "contract Vault { function set(uint256 amount) external {} }",
        require_pragma=True,
    )

    assert result["success"] is False
    assert result["error"] == "unverified: no compatible compiler installed."


def test_original_detector_ids_must_disappear(monkeypatch):
    result = _verify(
        monkeypatch,
        ORIGINAL,
        detector_checks=["reentrancy-eth"],
        target_checks=["reentrancy-eth"],
    )

    assert result["patch_verified"] is False
    assert result["patch_verification_status"] == "failed"
    assert result["remaining_checks"] == ["reentrancy-eth"]
    assert "Original Slither detector IDs remain" in result["patch_verification_details"]


def test_new_high_medium_finding_is_rejected(monkeypatch):
    result = _verify(
        monkeypatch,
        ORIGINAL,
        detectors=[{"check": "new-high-risk", "impact": "High"}],
        detector_checks=["new-high-risk"],
        target_checks=[],
    )

    assert result["patch_verified"] is False
    assert "High/Medium" in result["patch_verification_details"]


def test_missing_overloaded_public_function_is_rejected(monkeypatch):
    patched = ORIGINAL.replace(
        "    function set(address account) external {}\n",
        "",
    )
    result = _verify(monkeypatch, patched, target_checks=[])

    assert result["patch_verified"] is False
    assert result["surface_removed"] == ["set(address)"]


def test_patch_is_verified_only_when_all_gates_pass(monkeypatch):
    result = _verify(monkeypatch, ORIGINAL, target_checks=[])

    assert result["patch_verified"] is True
    assert result["patch_verification_status"] == "verified"
    assert result["remaining_checks"] == []
    assert result["surface_removed"] == []
    assert result["gutted_functions"] == []


def test_verify_patch_surfaces_exact_missing_compiler_reason(monkeypatch):
    monkeypatch.setattr(slither_runner, "_extract_solc_version", lambda _source: None)
    result = verify_patch(ORIGINAL, original_code=ORIGINAL)

    assert result["patch_verified"] is False
    assert result["patch_verification_details"] == "unverified: no compatible compiler installed."
    assert result["verification_error_kind"] == "compile_failed"


def test_receive_and_fallback_are_preserved_entry_points(monkeypatch):
    original = """
    pragma solidity ^0.8.20;
    contract Receiver {
        receive() external payable { }
        fallback() external { revert(); }
    }
    """
    patched = original.replace("        receive() external payable { }\n", "")
    monkeypatch.setattr(
        slither_runner,
        "run_slither",
        lambda *_args, **_kwargs: _slither_result(),
    )
    result = verify_patch(
        patched,
        target_checks=[],
        original_code=original,
    )

    assert result["patch_verified"] is False
    assert result["surface_removed"] == ["receive()"]

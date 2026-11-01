import main


def test_consolidated_patch_runs_f3_once(monkeypatch):
    calls = []
    monkeypatch.setattr(main, "ENABLE_SLITHER", True)
    monkeypatch.setattr(main, "is_slither_available", lambda: True)
    monkeypatch.setattr(main, "public_entry_points", lambda code: ["withdraw"])
    def fake_verify(code, **kwargs):
        calls.append(code)
        return {
            "patch_verified": True,
            "patch_verification_status": "verified",
            "patch_verification_details": "No target findings remain.",
            "remaining_checks": [],
            "behaviour_lite_passed": True,
            "surface_removed": [],
            "gutted_functions": [],
        }
    monkeypatch.setattr(main, "verify_patch", fake_verify)
    original = "contract Vault { function withdraw() external {} }"
    patch = "contract Vault { function withdraw() external { require(true); } }"
    result = main.verify_consolidated_patch(patch, original, [], True)
    assert calls == [patch]
    assert result.patch_verified is True
    assert "withdraw" in result.diff


def test_consolidated_patch_diff_is_unified():
    diff = main._unified_diff("contract A {}", "contract A { function x() external {} }")
    assert diff.startswith("--- original.sol")
    assert "+++ failed_patch.sol" in diff
    assert "+contract A { function x()" in diff


def test_consolidated_patch_skips_f3_when_model_only(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("F3 must not run for model-only analysis")
    monkeypatch.setattr(main, "verify_patch", unexpected)
    patch = "contract A { function x() external {} }"
    result = main.verify_consolidated_patch(patch, "contract A {}", [], False)
    assert result.patch_verified is False
    assert result.verification_status == "not_checked"
    assert result.failure_kind == "verification_skipped"


def test_retry_prompt_requests_one_integrated_contract():
    messages = main.build_retry_messages(
        original_code="contract A {}",
        failed_patch="contract A { function x() external {} }",
        failure_kind="still_vulnerable",
        remaining_checks=["reentrancy-eth"],
        details="Detector remains",
        findings_rows=[(0, {"title": "Reentrancy", "severity": "High", "what_to_do": "Use checks-effects-interactions."})],
    )
    prompt = messages[0]["content"]
    assert "ONE complete Solidity contract patch" in prompt
    assert '"consolidated_patch"' in prompt
    assert "findings" in messages[1]["content"]

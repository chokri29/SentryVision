"""Regression labels prioritize any newly introduced detector IDs."""

from main import classify_patch_verification


def _classify(remaining, baseline):
    return classify_patch_verification(
        patched_code="patched source",
        original_code="original source",
        patch_verification_status="failed",
        verification_error_kind=None,
        remaining_checks=remaining,
        original_high_medium_checks=baseline,
        retry_count=0,
    )


def test_mixed_original_and_new_findings_are_regression():
    result = _classify(["baseline-risk", "new-risk"], ["baseline-risk"])
    assert result["patch_failure_kind"] == "regression_introduced"
    assert result["retry_recommended"] is True


def test_only_original_findings_remain_still_vulnerable():
    result = _classify(["baseline-risk"], ["baseline-risk"])
    assert result["patch_failure_kind"] == "still_vulnerable"


def test_only_new_findings_are_regression():
    result = _classify(["new-risk"], ["baseline-risk"])
    assert result["patch_failure_kind"] == "regression_introduced"

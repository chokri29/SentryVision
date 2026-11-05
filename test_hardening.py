import pytest
import json
from types import SimpleNamespace

from fastapi.testclient import TestClient

import main
import slither_runner
import solc_util


def test_solc_range_selects_highest_installed_compatible_version(monkeypatch):
    monkeypatch.setattr(slither_runner, "_installed_solc_versions", lambda: ["0.8.20", "0.8.24", "0.8.26"])
    assert slither_runner._extract_solc_version("pragma solidity ^0.8.0;") == "0.8.26"
    assert slither_runner._extract_solc_version("pragma solidity ^0.8.26;") == "0.8.26"
    assert slither_runner._extract_solc_version("pragma solidity 0.8.20;") == "0.8.20"


def test_slither_normalizer_keeps_source_lines_confidence_and_elements():
    normalized = slither_runner._normalize_detectors({
        "results": {"detectors": [{
            "check": "reentrancy-eth",
            "impact": "High",
            "confidence": "High",
            "description": "External call before state update",
            "elements": [
                {"name": "withdraw", "source_mapping": {"lines": [12, 13]}},
                {"name": "balances", "source_mapping": {"lines": [13, 14]}},
            ],
        }]}
    })
    assert normalized[0]["lines"] == [12, 13, 14]
    assert normalized[0]["confidence"] == "High"
    assert normalized[0]["elements"] == ["balances", "withdraw"]


def test_client_ip_ignores_spoofable_x_forwarded_for(monkeypatch):
    from starlette.requests import Request
    monkeypatch.setattr(main, "TRUST_CF_CONNECTING_IP", False)
    request = Request({
        "type": "http", "http_version": "1.1", "method": "GET",
        "scheme": "https", "path": "/", "raw_path": b"/",
        "query_string": b"", "headers": [(b"x-forwarded-for", b"203.0.113.99")],
        "client": ("10.0.0.7", 1234), "server": ("test", 443),
    })
    assert main.get_client_ip(request) == "10.0.0.7"


def test_analyze_api_attaches_only_authoritative_slither_metadata(monkeypatch):
    main.analysis_store.clear()
    monkeypatch.setattr(main, "enforce_rate_limit", lambda _ip: None)
    monkeypatch.setattr(main, "ENABLE_SLITHER", True)
    monkeypatch.setattr(main, "is_slither_available", lambda: True)
    monkeypatch.setattr(main, "run_slither", lambda *_: {
        "success": True,
        "filtered_detectors": [{
            "check": "reentrancy-eth", "impact": "High", "confidence": "High",
            "description": "External call before state update", "lines": [8, 9],
        }],
        "detectors": [{
            "check": "reentrancy-eth", "impact": "High", "confidence": "High",
            "description": "External call before state update", "lines": [8, 9],
        }],
    })
    monkeypatch.setattr(main, "verify_consolidated_patch", lambda *a, **k: main.ConsolidatedPatch(
        code="contract Vault {}", verification_status="not_checked", failure_kind="verification_skipped"
    ))

    response_json = {
        "summary": "Reentrancy signal",
        "findings": [{
            "title": "Reentrancy", "severity": "Critical", "slither_check": "reentrancy-eth",
            "what_happens": "External call before state update",
            "why_it_matters": "May drain funds", "what_to_do": "Use CEI",
            "mermaid_diagram": "graph TD; A-->B",
        }],
        "consolidated_patch": None, "patch_change_summary": "",
    }
    fake_client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(
        create=lambda **kwargs: SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(response_json)))])
    )))
    monkeypatch.setattr(main.client, "_ensure", lambda: fake_client)

    client = TestClient(main.app)
    response = client.post("/analyze", json={"solidity_code": "pragma solidity ^0.8.0; contract Vault {}"})
    assert response.status_code == 200
    finding = response.json()["findings"][0]
    assert finding["grounding_status"] == "grounded"
    assert finding["severity"] == "High"
    assert finding["slither_check"] == "reentrancy-eth"
    assert finding["slither_lines"] == [8, 9]


def test_unmatched_model_finding_is_explicitly_ungrounded():
    finding = main.Finding(
        title="Model-only idea", severity="High", what_happens="x",
        why_it_matters="y", what_to_do="z", mermaid_diagram="graph TD; A-->B",
    )
    assert finding.grounding_status == "ungrounded"


def test_retry_endpoint_stops_after_success_and_exhausts_at_cap(monkeypatch):
    from fastapi import HTTPException

    row = {
        "created_at": 1,
        "retry_count": 0,
        "findings": [{
            "title": "Reentrancy", "severity": "High",
            "what_happens": "External call before state update",
            "why_it_matters": "Funds may be drained", "what_to_do": "Use CEI",
            "mermaid_diagram": "graph TD; A-->B",
            "grounding_status": "grounded", "slither_check": "reentrancy-eth",
            "slither_impact": "High", "slither_confidence": "High", "slither_lines": [8, 9],
        }],
        "original_code": "contract Vault { function withdraw() external {} }",
        "original_high_medium_checks": ["reentrancy-eth"],
        "slither_error": None,
        "summary": "Reentrancy",
        "consolidated_patch": {
            "code": "contract Vault { function withdraw() external {} }",
            "diff": "--- original.sol", "failure_kind": "still_vulnerable",
            "verification_status": "failed", "retry_available": True,
            "remaining_checks": ["reentrancy-eth"], "verification_details": "Detector remains",
        },
    }
    monkeypatch.setattr(main, "enforce_rate_limit", lambda _ip: None)
    monkeypatch.setattr(main, "get_analysis", lambda _analysis_id: row)
    monkeypatch.setattr(main.retry_client, "_ensure", lambda: SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=lambda **kwargs: SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps({
                "consolidated_patch": "contract Vault { function withdraw() external { require(true); } }",
                "change_summary": "Repaired", "unable_to_fix": False, "unable_reason": None,
            })))]
        )))
    ))
    monkeypatch.setattr(main, "verify_consolidated_patch", lambda *a, **k: main.ConsolidatedPatch(
        code="contract Vault { function withdraw() external { require(true); } }",
        diff="--- original.sol", patch_verified=True, verification_status="verified",
        change_summary="Repaired",
    ))
    monkeypatch.setattr(main, "update_analysis", lambda _analysis_id, updated: row.update(updated))
    client = TestClient(main.app)

    first = client.post("/analyze/test-id/retry-patch")
    assert first.status_code == 200
    assert first.json()["meta"]["retry_count"] == 1
    assert first.json()["meta"]["retry_available"] is False
    assert row["retry_count"] == 1

    second = client.post("/analyze/test-id/retry-patch")
    assert second.status_code == 400
    assert "not eligible" in second.json()["detail"].lower()

    row["retry_count"] = main.MAX_PATCH_RETRIES
    exhausted = client.post("/analyze/test-id/retry-patch")
    assert exhausted.status_code == 400
    assert "exhausted" in exhausted.json()["detail"].lower()


def test_redis_daily_ai_budget_is_global_and_enforced(monkeypatch):
    class FakeRedis:
        def eval(self, *_args):
            return [2, 101]

    monkeypatch.setattr(main, "_redis", lambda: FakeRedis())
    monkeypatch.setattr(main, "MAX_DAILY_AI_CALLS", 100)
    from fastapi import HTTPException
    import pytest
    with pytest.raises(HTTPException) as exc:
        main.enforce_rate_limit("198.51.100.7")
    assert exc.value.status_code == 429
    assert "Daily AI usage limit" in exc.value.detail



def test_rate_limit_is_configurable_and_returns_retry_after(monkeypatch):
    from fastapi import HTTPException
    monkeypatch.setattr(main, "MAX_REQUESTS_PER_WINDOW", 6)
    class LimitedRedis:
        def eval(self, *_args):
            return [-1, 0]
    monkeypatch.setattr(main, "_redis", lambda: LimitedRedis())
    with pytest.raises(HTTPException) as exc:
        main.enforce_rate_limit("198.51.100.9")
    assert exc.value.status_code == 429
    assert exc.value.headers["Retry-After"] == "60"


def test_redis_failure_fails_closed_before_model_call(monkeypatch):
    from fastapi import HTTPException
    monkeypatch.setattr(main, "REQUIRE_SHARED_STORAGE", True)
    monkeypatch.setattr(main.os, "getenv", lambda key, default=None: "true" if key == "REQUIRE_REDIS_RATE_LIMIT" else default)
    class BrokenRedis:
        def eval(self, *_args):
            raise ConnectionError("redis unavailable")
    monkeypatch.setattr(main, "_redis", lambda: BrokenRedis())
    with pytest.raises(HTTPException) as exc:
        main.enforce_rate_limit("198.51.100.10")
    assert exc.value.status_code == 503


def test_missing_retry_state_has_clear_expired_message(monkeypatch):
    monkeypatch.setattr(main, "enforce_rate_limit", lambda _ip: None)
    monkeypatch.setattr(main, "get_analysis", lambda _analysis_id: None)
    response = TestClient(main.app).post("/analyze/expired-id/retry-patch")
    assert response.status_code == 404
    assert "expired" in response.json()["detail"].lower()
    assert "run the analysis again" in response.json()["detail"].lower()


def test_solc_select_inventory_is_not_trusted_without_binary(monkeypatch):
    from pathlib import Path
    monkeypatch.setattr(solc_util, "_solc_roots", lambda: [])
    monkeypatch.setattr(solc_util, "solc_select_installed_versions", lambda: ["0.8.0", "0.8.38"])
    monkeypatch.setattr(solc_util, "path_solc_info", lambda: (None, None))
    monkeypatch.setattr(
        solc_util, "solc_artifact_path",
        lambda version: Path("/verified/solc") if version == "0.8.38" else None,
    )
    assert solc_util.installed_solc_versions() == ["0.8.38"]


def test_solc_util_uses_highest_installed_for_caret_and_no_pragma(monkeypatch):
    monkeypatch.setattr(solc_util, "installed_solc_versions", lambda: ["0.8.20", "0.8.38"])
    assert solc_util.extract_solc_version("pragma solidity ^0.8.0; contract Vault {}") == "0.8.38"
    assert solc_util.extract_solc_version("contract LegacyLottery {}") == "0.8.38"


@pytest.mark.parametrize(
    "source",
    [
        "pragma solidity ^0.8.0; contract Vault {}",
        "contract LegacyLottery {}",
    ],
)
def test_f1_pins_source_to_verified_compiler_before_python_api(monkeypatch, source):
    captured = {}
    monkeypatch.setattr(slither_runner, "_installed_solc_versions", lambda: ["0.8.38"])
    monkeypatch.setattr(slither_runner, "_resolve_solc_binary", lambda version: (version, "/verified/solc-0.8.38"))
    monkeypatch.setattr(slither_runner, "is_slither_available", lambda: True)

    def fake_api(sol_file, solc_bin):
        captured["source"] = sol_file.read_text(encoding="utf-8")
        captured["binary"] = solc_bin
        return {
            "success": True, "detectors": [{"check": "reentrancy-eth"}],
            "filtered_detectors": [{"check": "reentrancy-eth"}],
            "detector_checks": ["reentrancy-eth"], "count": 1, "filtered_count": 1,
            "raw": {"via": "python_api"}, "error": None, "error_kind": None,
        }

    monkeypatch.setattr(slither_runner, "_run_slither_python_api", fake_api)
    result = slither_runner.run_slither(source, "Vault.sol")
    assert result["success"] is True
    assert result["detector_checks"] == ["reentrancy-eth"]
    assert captured["binary"] == "/verified/solc-0.8.38"
    assert captured["source"].startswith("pragma solidity 0.8.38;")


def test_python_api_retries_compiler_mismatch_once(monkeypatch, tmp_path):
    import subprocess
    import slither.slither
    calls = []

    class FakeSlither:
        def __init__(self, source_path, **kwargs):
            calls.append((Path(source_path).read_text(encoding="utf-8"), kwargs.get("solc")))
            if len(calls) == 1:
                raise RuntimeError("solc 0.8.0 not installed, only 0.8.38 available")

        def register_detector(self, _detector):
            return None

        def run_detectors(self):
            return []

    from pathlib import Path
    source = tmp_path / "Legacy.sol"
    source.write_text("pragma solidity ^0.8.0; contract Legacy {}", encoding="utf-8")
    monkeypatch.setattr(slither.slither, "Slither", FakeSlither)
    monkeypatch.setattr(slither_runner, "_util_installed_solc_versions", lambda: ["0.8.38"])
    monkeypatch.setattr(slither_runner, "_util_resolve_solc_binary", lambda version: (version, "/verified/solc-0.8.38"))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""))

    result = slither_runner._run_slither_python_api(source, "/missing/solc-0.8.0")
    assert result["success"] is True
    assert len(calls) == 2
    assert calls[1][0].startswith("pragma solidity 0.8.38;")
    assert calls[1][1] == "/verified/solc-0.8.38"


def test_builtin_detector_loader_enumerates_classes_from_slither_module():
    class AbstractDetector:
        pass

    class ReentrancyEth(AbstractDetector):
        ARGUMENT = "reentrancy-eth"

    class Unrelated:
        pass

    module = SimpleNamespace(
        AbstractDetector=AbstractDetector,
        ReentrancyEth=ReentrancyEth,
        Unrelated=Unrelated,
    )
    assert slither_runner._builtin_detector_classes(module, AbstractDetector) == [ReentrancyEth]


def test_python_api_registers_builtin_detectors_before_running(monkeypatch, tmp_path):
    import slither.slither
    registered = []

    class FakeDetector:
        ARGUMENT = "reentrancy-eth"

    class FakeSlither:
        def __init__(self, _source_path, **_kwargs):
            pass

        def register_detector(self, detector_class):
            registered.append(detector_class)

        def run_detectors(self):
            return [[{
                "check": "reentrancy-eth",
                "impact": "High",
                "confidence": "High",
                "description": "External call before state update",
                "elements": [],
            }]]

    source = tmp_path / "Vault.sol"
    source.write_text("pragma solidity 0.8.38; contract Vault {}", encoding="utf-8")
    monkeypatch.setattr(slither.slither, "Slither", FakeSlither)
    monkeypatch.setattr(slither_runner, "_builtin_detector_classes", lambda: [FakeDetector])

    result = slither_runner._run_slither_python_api(source, None)

    assert registered == [FakeDetector]
    assert result["success"] is True
    assert result["detector_registry_count"] == 1
    assert result["count"] == 1
    assert result["filtered_count"] == 1
    assert result["detector_checks"] == ["reentrancy-eth"]


def test_python_api_fails_closed_when_no_builtin_detectors_register(monkeypatch, tmp_path):
    import slither.slither

    class FakeSlither:
        def __init__(self, _source_path, **_kwargs):
            pass

        def run_detectors(self):
            return []

    source = tmp_path / "Vault.sol"
    source.write_text("pragma solidity 0.8.38; contract Vault {}", encoding="utf-8")
    monkeypatch.setattr(slither.slither, "Slither", FakeSlither)
    monkeypatch.setattr(slither_runner, "_builtin_detector_classes", lambda: [])

    result = slither_runner._run_slither_python_api(source, None)

    assert result["success"] is False
    assert result["error_kind"] == "execution_error"
    assert "loaded no built-in detectors" in result["error"]


def test_empty_filtered_detector_set_does_not_fall_back_to_raw_hits():
    result = {
        "detectors": [{"check": "reentrancy-eth", "impact": "High"}],
        "filtered_detectors": [],
    }
    assert main._f1_findings_for_prompt(result) == []


def test_filtered_detector_set_is_used_for_f1_grounding():
    filtered = [{"check": "reentrancy-eth", "impact": "High"}]
    result = {
        "detectors": filtered + [{"check": "naming-convention", "impact": "Informational"}],
        "filtered_detectors": filtered,
    }
    assert main._f1_findings_for_prompt(result) == filtered

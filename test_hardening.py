import json
from types import SimpleNamespace

from fastapi.testclient import TestClient

import main
import slither_runner


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

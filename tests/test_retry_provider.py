"""Tests that the optional Muse Wonder retry uses an isolated Meta API client."""

import pytest
from fastapi import HTTPException
from starlette.requests import Request

import main


def test_provider_clients_use_independent_credentials_and_endpoints(monkeypatch):
    created = []

    class FakeOpenAI:
        def __init__(self, *, api_key, base_url):
            created.append((api_key, base_url))

    monkeypatch.setattr(main, "OpenAI", FakeOpenAI)
    baseten = main.LazyOpenAIClient(
        api_key="baseten-test-key",
        base_url="https://inference.baseten.co/v1",
        key_env_name="LLM_API_KEY",
    )
    meta = main.LazyOpenAIClient(
        api_key="meta-test-key",
        base_url="https://api.meta.ai/v1",
        key_env_name="LLM_RETRY_API_KEY",
    )

    baseten._ensure()
    meta._ensure()

    assert created == [
        ("baseten-test-key", "https://inference.baseten.co/v1"),
        ("meta-test-key", "https://api.meta.ai/v1"),
    ]
    assert baseten._client is not meta._client


def test_meta_client_fails_closed_when_retry_key_is_missing(monkeypatch):
    created = []
    monkeypatch.setattr(main, "OpenAI", lambda **kwargs: created.append(kwargs))

    meta = main.LazyOpenAIClient(
        api_key=None,
        base_url="https://api.meta.ai/v1",
        key_env_name="LLM_RETRY_API_KEY",
    )

    with pytest.raises(RuntimeError, match="LLM_RETRY_API_KEY"):
        meta._ensure()
    assert created == []


def test_retry_endpoint_does_not_fall_back_to_baseten_when_meta_is_unconfigured(monkeypatch):
    row = {
        "retry_count": 0,
        "findings": [{
            "title": "Reentrancy",
            "severity": "High",
            "what_happens": "External call before state update.",
            "why_it_matters": "Funds may be drained.",
            "what_to_do": "Apply checks-effects-interactions.",
            "mermaid_diagram": "graph TD; A-->B",
            "patched_code": "contract C {}",
            "patch_verification_status": "failed",
            "patch_failure_kind": "still_vulnerable",
            "retry_recommended": True,
            "retry_available": True,
            "retry_count": 0,
        }],
        "original_code": "contract C {}",
        "original_high_medium_checks": [],
        "slither_error": None,
        "summary": "Test",
    }
    monkeypatch.setattr(main, "get_analysis", lambda _analysis_id: row)
    monkeypatch.setattr(main, "enforce_rate_limit", lambda _ip: None)

    def meta_not_configured():
        raise RuntimeError("Missing env var(s): LLM_RETRY_API_KEY")

    def baseten_must_not_be_used():
        pytest.fail("Retry path incorrectly attempted to use the Baseten client")

    monkeypatch.setattr(main.retry_client, "_ensure", meta_not_configured)
    monkeypatch.setattr(main.client, "_ensure", baseten_must_not_be_used)

    request = Request({
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/analyze/test-analysis/retry-patch",
        "raw_path": b"/analyze/test-analysis/retry-patch",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    })

    with pytest.raises(HTTPException) as exc:
        main.retry_patch("test-analysis", request)

    assert exc.value.status_code == 503
    assert "LLM_RETRY_API_KEY" in exc.value.detail

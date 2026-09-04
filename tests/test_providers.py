import json

import httpx
import pytest

from netlens.config import Settings
from netlens.detectors import analyze
from netlens.parsing import parse_capture
from netlens.providers.base import ProviderError, prepare_context
from netlens.providers.gateway import generate_report
from netlens.providers.mock import MockProvider
from netlens.schemas import ReportContent


@pytest.fixture
def context():
    from pathlib import Path

    stats, findings = analyze(parse_capture(Path("demo/captures/dns_failure.pcap"), Settings()))
    context, mapping = prepare_context(stats.model_dump(), [f.model_dump() for f in findings])
    assert "192.0.2.1" in mapping
    assert "192.0.2.1" not in json.dumps(context)
    assert "example.test" not in json.dumps(context)
    return context


def envelope(provider, content):
    if provider == "openai":
        return {
            "status": "completed",
            "model": "test-openai",
            "output": [{"type": "message", "content": [{"type": "output_text", "text": content}]}],
            "usage": {"input_tokens": 100, "output_tokens": 50, "total_tokens": 150},
        }
    if provider == "anthropic":
        return {
            "stop_reason": "end_turn",
            "content": [{"type": "text", "text": content}],
            "usage": {"input_tokens": 100, "output_tokens": 50},
        }
    return {"done": True, "message": {"content": content}, "eval_count": 50}


@pytest.mark.parametrize("provider", ["mock", "openai", "anthropic", "ollama"])
def test_success(provider, context):
    expected = MockProvider().generate(context).content.model_dump_json()

    def handle(request):
        data = json.loads(request.content)
        assert "192.0.2.1" not in request.content.decode()
        assert "schema" in str(data) or provider == "ollama"
        if provider == "anthropic":

            def check(schema):
                if isinstance(schema, dict):
                    assert not {"minLength", "maxLength", "maxItems"} & schema.keys()
                    for value in schema.values():
                        check(value)
                elif isinstance(schema, list):
                    for value in schema:
                        check(value)

            check(data["output_config"]["format"]["schema"])
        return httpx.Response(200, json=envelope(provider, expected))

    content, metadata = generate_report(
        provider,
        context,
        Settings(openai_api_key="fake-test", anthropic_api_key="fake-test"),
        httpx.MockTransport(handle),
    )
    assert ReportContent.model_validate(content)
    assert metadata.estimated_cost_usd is None
    assert metadata.usage is None if provider == "mock" else metadata.usage


@pytest.mark.parametrize("provider", ["openai", "anthropic", "ollama"])
@pytest.mark.parametrize("failure", ["timeout", "rate_limit", "malformed", "bad_refs", "http"])
def test_failures(provider, failure, context, monkeypatch):
    monkeypatch.setattr("netlens.providers.gateway.time.sleep", lambda _: None)
    calls = []

    def handle(request):
        calls.append(request)
        if failure == "timeout":
            raise httpx.ReadTimeout("private provider response")
        if failure in ("rate_limit", "http"):
            return httpx.Response(429 if failure == "rate_limit" else 503)
        content = MockProvider().generate(context).content.model_dump()
        if failure == "bad_refs":
            content["observed_issues"][0]["finding_ids"] = ["nonexistent"]
        text = "not-json" if failure == "malformed" else json.dumps(content)
        return httpx.Response(200, json=envelope(provider, text))

    with pytest.raises(ProviderError) as exc:
        generate_report(
            provider,
            context,
            Settings(openai_api_key="fake", anthropic_api_key="fake"),
            httpx.MockTransport(handle),
        )
    assert "private" not in str(exc.value)
    assert len(calls) == (3 if failure in ("timeout", "rate_limit", "http") else 1)


def test_retry_success_and_explicit_fallback(context, monkeypatch):
    monkeypatch.setattr("netlens.providers.gateway.time.sleep", lambda _: None)
    calls = []

    def handle(request):
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(429)
        return httpx.Response(
            200, json=envelope("openai", MockProvider().generate(context).content.model_dump_json())
        )

    _, meta = generate_report(
        "openai", context, Settings(openai_api_key="fake"), httpx.MockTransport(handle)
    )
    assert len(calls) == 2
    assert meta.fallback_from is None
    _, meta = generate_report("openai", context, Settings(fallback_provider="mock"))
    assert meta.provider == "mock" and meta.fallback_from == "openai"


def test_original_constraints_still_validated(context):
    content = MockProvider().generate(context).content.model_dump()
    content["summary"] = "x" * 4001

    def handle(request):
        return httpx.Response(200, json=envelope("anthropic", json.dumps(content)))

    with pytest.raises(ProviderError, match="malformed_provider_output"):
        generate_report(
            "anthropic", context, Settings(anthropic_api_key="fake"), httpx.MockTransport(handle)
        )

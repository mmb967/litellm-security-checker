import json

import pytest

from warden.gateway.cache import ResponseCache
from warden.gateway.catalog import ModelCatalog, ModelEntry
from warden.gateway.gateway import GatewayError, LLMGateway, RetryPolicy
from warden.gateway.limits import LimitExceeded, Limiter
from warden.gateway.pii import PIIVault
from warden.gateway.providers import OpenAICompatibleProvider, ScriptedProvider
from warden.gateway.types import (
    ChatRequest,
    Message,
    ProviderError,
    TextBlock,
    ToolCall,
    ToolResult,
)
from warden.locality import NonLocalEndpointError
from warden.observability.audit import AuditLog
from warden.security.principal import Principal, RunContext

RUN = RunContext("run_x", "triage", Principal("alice", "user", frozenset(), frozenset(),
                                               frozenset()), "incident_response", "test")


def entry(alias, markings=("PROD",), url="http://127.0.0.1:11434/v1"):
    return ModelEntry(alias=alias, provider="openai_compatible", model=alias, base_url=url,
                      allowed_markings=frozenset(markings))


def gw(provider, *entries, **kw):
    cat = ModelCatalog({e.alias: e for e in (entries or [entry("m")])})
    return LLMGateway(cat, {"openai_compatible": provider}, sleep=lambda s: None,
                      retry=RetryPolicy(max_attempts=3), **kw)


def req(text="hi", model="m"):
    return ChatRequest(model=model, system="sys", messages=[Message("user", [TextBlock(text)])])


# -- PII -----------------------------------------------------------------------

def test_pii_round_trip_and_secrets_are_irreversible():
    v = PIIVault()
    masked = v.mask_text("mail a@b.com key AKIAIOSFODNN7EXAMPLE card 4111 1111 1111 1111 ip 10.1.2.3")
    assert "a@b.com" not in masked and "AKIA" not in masked and "4111" not in masked
    assert "<EMAIL_1>" in masked and "<SECRET_1>" in masked and "<CARD_1>" in masked
    back = v.unmask_text(masked)
    assert "a@b.com" in back and "4111 1111 1111 1111" in back
    assert "AKIA" not in back  # secrets never come back


def test_non_luhn_digit_runs_are_not_cards():
    assert "<CARD" not in PIIVault().mask_text("order 1234567890123")


def test_pii_never_reaches_provider_and_tool_args_are_unmasked():
    def responder(r):
        return [ToolCall("c1", "notify_owner", {"asset_id": "A-1", "message": "cc <EMAIL_1>"})]

    sp = ScriptedProvider(responder)
    v = PIIVault()
    out = gw(sp).complete(req("owner is jo@corp.io"), run=RUN, vault=v)
    wire = str(sp.requests[0].messages)
    assert "jo@corp.io" not in wire and "<EMAIL_1>" in wire
    assert out.tool_calls[0].input["message"] == "cc jo@corp.io"


# -- retry / fallback ----------------------------------------------------------

def test_retries_retryable_errors_then_succeeds():
    calls = {"n": 0}

    def responder(r):
        calls["n"] += 1
        if calls["n"] < 3:
            raise ProviderError("overloaded", retryable=True)
        return [TextBlock("ok")]

    assert gw(ScriptedProvider(responder)).complete(req(), run=RUN, vault=PIIVault()).text == "ok"
    assert calls["n"] == 3


def test_non_retryable_error_falls_back_to_next_model():
    def responder(r):
        if r.model == "a":
            raise ProviderError("bad request", retryable=False)
        return [TextBlock(f"from {r.model}")]

    g = gw(ScriptedProvider(responder), entry("a"), entry("b"))
    out = g.complete(req(model="a"), run=RUN, vault=PIIVault(), fallbacks=["b"])
    assert out.text == "from b" and out.model_alias == "b"


def test_data_residency_skips_models_not_cleared_for_taint():
    sp = ScriptedProvider(lambda r: [TextBlock(r.model)])
    g = gw(sp, entry("shared"), entry("enclave", ("PROD", "EXPORT_CONTROLLED"), "http://10.20.0.5/v1"))
    out = g.complete(req(model="shared"), run=RUN, vault=PIIVault(),
                     taint=frozenset({"EXPORT_CONTROLLED"}), fallbacks=["enclave"])
    assert out.model_alias == "enclave"
    with pytest.raises(GatewayError, match="not cleared"):
        g.complete(req(model="shared"), run=RUN, vault=PIIVault(),
                   taint=frozenset({"EXPORT_CONTROLLED"}))


# -- local only ----------------------------------------------------------------

def test_non_local_model_refused_at_startup():
    with pytest.raises(NonLocalEndpointError):
        gw(ScriptedProvider(lambda r: []), entry("cloud", url="https://api.example.com/v1"))


def test_runtime_registered_non_local_model_refused_per_call():
    g = gw(ScriptedProvider(lambda r: [TextBlock("x")]))
    g.catalog.register(entry("sneaky", url="https://api.example.com/v1"))
    with pytest.raises(NonLocalEndpointError):
        g.complete(req(model="sneaky"), run=RUN, vault=PIIVault())


def test_http_client_ignores_proxy_env(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.com:3128")
    assert OpenAICompatibleProvider().http._trust_env is False


# -- cache / limits / audit ----------------------------------------------------

def test_cache_hit_skips_provider_and_stores_masked():
    sp = ScriptedProvider(lambda r: [TextBlock("reply to <EMAIL_1>")])
    cache = ResponseCache()
    g = gw(sp, cache=cache)
    a = g.complete(req("x@y.com"), run=RUN, vault=PIIVault(), use_cache=True)
    b = g.complete(req("x@y.com"), run=RUN, vault=PIIVault(), use_cache=True)
    assert len(sp.requests) == 1 and b.cached and a.text == b.text == "reply to x@y.com"
    assert "x@y.com" not in str(cache._data)


def test_daily_token_budget_is_enforced():
    lim = Limiter(requests_per_minute=1000, daily_tokens_per_agent={"triage": 150},
                  default_daily_tokens=10)
    g = gw(ScriptedProvider(lambda r: [TextBlock("x")]), limiter=lim)
    g.complete(req(), run=RUN, vault=PIIVault())  # scripted usage = 120 tokens
    g.complete(req(), run=RUN, vault=PIIVault())
    with pytest.raises(LimitExceeded, match="daily budget"):
        g.complete(req(), run=RUN, vault=PIIVault())


def test_llm_calls_are_audited_with_usage():
    audit = AuditLog()
    gw(ScriptedProvider(lambda r: [TextBlock("x")]), audit=audit).complete(
        req(), run=RUN, vault=PIIVault())
    ev = [e for e in audit.events if e["event"] == "llm_call"][0]
    assert ev["input_tokens"] == 100 and ev["output_tokens"] == 20 and ev["run_id"] == "run_x"


def test_openai_wire_format_round_trip():
    msgs = [Message("user", [TextBlock("q")]),
            Message("assistant", [ToolCall("t1", "get_asset", {"asset_id": "A-1"})]),
            Message("user", [ToolResult("t1", "boom", is_error=True)])]
    wire = OpenAICompatibleProvider._to_wire("sys", msgs)
    assert [m["role"] for m in wire] == ["system", "user", "assistant", "tool"]
    assert wire[2]["tool_calls"][0]["function"]["arguments"] == '{"asset_id": "A-1"}'
    assert wire[3] == {"role": "tool", "tool_call_id": "t1", "content": "ERROR: boom"}


def test_openai_compatible_provider_against_mock_local_server():
    import httpx

    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={
            "model": "qwen3:32b",
            "choices": [{"finish_reason": "tool_calls", "message": {
                "content": "<think>internal reasoning</think>Checking.",
                "tool_calls": [{"id": "call_1", "type": "function", "function": {
                    "name": "get_asset", "arguments": '{"asset_id": "A-001"}'}}]}}],
            "usage": {"prompt_tokens": 321, "completion_tokens": 12},
        })

    provider = OpenAICompatibleProvider(httpx.Client(transport=httpx.MockTransport(handler)))
    from warden.gateway.types import ToolSpec
    r = ChatRequest(model="m", system="sys", messages=[Message("user", [TextBlock("q")])],
                    tools=[ToolSpec("get_asset", "d", {"type": "object"})])
    out = provider.complete(entry("m"), r)
    assert seen["url"] == "http://127.0.0.1:11434/v1/chat/completions"
    assert seen["body"]["tools"][0]["function"]["name"] == "get_asset"
    assert out.stop_reason == "tool_use" and out.text == "Checking."
    assert out.tool_calls[0].input == {"asset_id": "A-001"}
    assert (out.usage.input_tokens, out.usage.output_tokens) == (321, 12)


def test_provider_maps_429_and_5xx_to_retryable():
    import httpx

    for status, retryable in ((429, True), (503, True), (400, False)):
        client = httpx.Client(transport=httpx.MockTransport(lambda req, s=status: httpx.Response(s)))
        with pytest.raises(ProviderError) as e:
            OpenAICompatibleProvider(client).complete(entry("m"), req())
        assert e.value.retryable is retryable

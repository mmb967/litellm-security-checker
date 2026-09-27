"""Provider adapters. Each translates neutral types <-> one wire format.

Everything runs locally, so there is one real transport: the OpenAI-style
/chat/completions HTTP API that every local inference server speaks (Ollama,
vLLM, llama.cpp server, LM Studio, TGI). Adding another local runtime with a
different API means adding one class here; nothing above the gateway changes.

Retries are owned by the gateway (one place for backoff, accounting and
fallback), so the HTTP client here does not retry.
"""

from __future__ import annotations

import json
import os
import re
from typing import Callable, Protocol

from warden.gateway.catalog import ModelEntry
from warden.gateway.types import (
    Block,
    ChatRequest,
    ChatResponse,
    Message,
    ProviderError,
    TextBlock,
    ToolCall,
    ToolResult,
    Usage,
)


# Reasoning models served locally (Qwen3, DeepSeek-R1 distills) may inline their
# chain of thought. It is not part of the answer and is not replayed.
_THINK_RE = re.compile(r"<think>.*?</think>", re.S)


class Provider(Protocol):
    name: str

    def complete(self, entry: ModelEntry, req: ChatRequest) -> ChatResponse: ...


# ---------------------------------------------------------------------------
# Local inference servers speaking OpenAI-style /chat/completions.
# ---------------------------------------------------------------------------


class OpenAICompatibleProvider:
    name = "openai_compatible"

    def __init__(self, http_client=None):
        self._http = http_client

    @property
    def http(self):
        if self._http is None:
            import httpx

            # trust_env=False: ignore HTTP(S)_PROXY / netrc from the environment,
            # so a proxy setting can never route local inference traffic off-box.
            self._http = httpx.Client(timeout=300, trust_env=False)
        return self._http

    @staticmethod
    def _to_wire(system: str, messages: list[Message]) -> list[dict]:
        out: list[dict] = [{"role": "system", "content": system}]
        for m in messages:
            texts = [b.text for b in m.content if isinstance(b, TextBlock)]
            calls = [b for b in m.content if isinstance(b, ToolCall)]
            results = [b for b in m.content if isinstance(b, ToolResult)]
            if m.role == "assistant":
                msg: dict = {"role": "assistant", "content": "\n".join(texts) or None}
                if calls:
                    msg["tool_calls"] = [
                        {"id": c.id, "type": "function",
                         "function": {"name": c.name, "arguments": json.dumps(c.input)}}
                        for c in calls
                    ]
                out.append(msg)
            else:
                for r in results:
                    content = f"ERROR: {r.content}" if r.is_error else r.content
                    out.append({"role": "tool", "tool_call_id": r.tool_call_id, "content": content})
                if texts:
                    out.append({"role": "user", "content": "\n".join(texts)})
        return out

    def complete(self, entry: ModelEntry, req: ChatRequest) -> ChatResponse:
        import httpx

        if not entry.base_url:
            raise ProviderError(f"model '{entry.alias}' has no base_url", retryable=False)
        headers = {}
        if entry.api_key_env and os.environ.get(entry.api_key_env):
            headers["Authorization"] = f"Bearer {os.environ[entry.api_key_env]}"
        body: dict = {
            "model": entry.model,
            "max_tokens": req.max_tokens or entry.max_tokens,
            "messages": self._to_wire(req.system, req.messages),
            **{k: v for k, v in entry.params.items() if k in ("temperature", "top_p")},
        }
        if req.tools:
            body["tools"] = [
                {"type": "function",
                 "function": {"name": t.name, "description": t.description, "parameters": t.input_schema}}
                for t in req.tools
            ]
        try:
            r = self.http.post(f"{entry.base_url.rstrip('/')}/chat/completions", json=body, headers=headers)
        except httpx.TransportError as e:
            raise ProviderError(str(e), retryable=True) from e
        if r.status_code == 429:
            ra = r.headers.get("retry-after")
            raise ProviderError("rate limited", retryable=True, retry_after=float(ra) if ra else None)
        if r.status_code >= 400:
            raise ProviderError(f"HTTP {r.status_code}: {r.text[:500]}", retryable=r.status_code >= 500)

        data = r.json()
        choice = data["choices"][0]
        msg = choice["message"]
        content: list[Block] = []
        text = _THINK_RE.sub("", msg.get("content") or "").strip()
        if text:
            content.append(TextBlock(text))
        for tc in msg.get("tool_calls") or []:
            try:
                args = json.loads(tc["function"]["arguments"] or "{}")
            except json.JSONDecodeError:
                args = {"__invalid_json__": tc["function"]["arguments"]}
            call_id = tc.get("id") or f"call_{len(content)}"  # some servers omit ids
            content.append(ToolCall(id=call_id, name=tc["function"]["name"], input=args))
        stop = {"tool_calls": "tool_use", "stop": "end_turn", "length": "max_tokens",
                "content_filter": "refusal"}.get(choice.get("finish_reason"), "end_turn")
        usage = data.get("usage") or {}
        return ChatResponse(
            content=content,
            stop_reason=stop,
            usage=Usage(usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0)),
            model_alias=entry.alias,
            provider_model=data.get("model", entry.model),
            provider=self.name,
        )


# ---------------------------------------------------------------------------
# Deterministic provider for unit tests and offline harness checks.
# ---------------------------------------------------------------------------


class ScriptedProvider:
    """Replies are produced by a Python callable over the (masked) request.

    This is what the model provider sees, so tests can assert that PII never
    reaches it by inspecting `self.requests`.
    """

    name = "scripted"

    def __init__(self, responder: Callable[[ChatRequest], list[Block]]):
        self._responder = responder
        self.requests: list[ChatRequest] = []

    def complete(self, entry: ModelEntry, req: ChatRequest) -> ChatResponse:
        self.requests.append(req)
        blocks = self._responder(req)
        stop = "tool_use" if any(isinstance(b, ToolCall) for b in blocks) else "end_turn"
        return ChatResponse(
            content=blocks,
            stop_reason=stop,
            usage=Usage(input_tokens=100, output_tokens=20),
            model_alias=entry.alias,
            provider_model=entry.model,
            provider=self.name,
        )


def default_providers() -> dict[str, Provider]:
    return {"openai_compatible": OpenAICompatibleProvider()}

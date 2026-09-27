"""The single choke point between agents and models.

Every LLM call in the system goes through `LLMGateway.complete()`:

    local-only check -> data-residency check -> PII/secret masking -> cache -> rate limit / budget
      -> provider call with retry+backoff -> model fallback chain
      -> usage + cost accounting -> audit + trace -> unmask

Nothing else in the codebase imports a provider SDK.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, replace
from typing import Callable

from warden.gateway.cache import ResponseCache, cache_key
from warden.gateway.catalog import ModelCatalog, ModelEntry
from warden.gateway.limits import Limiter
from warden.locality import assert_local
from warden.gateway.pii import PIIVault
from warden.gateway.providers import Provider
from warden.gateway.types import (
    Block,
    ChatRequest,
    ChatResponse,
    Message,
    ProviderError,
    TextBlock,
    ToolCall,
    ToolResult,
)
from warden.observability.audit import AuditLog
from warden.observability.tracing import tracer
from warden.security.principal import RunContext


class GatewayError(Exception):
    pass


@dataclass
class RetryPolicy:
    max_attempts: int = 4
    base_delay_s: float = 1.0
    max_delay_s: float = 30.0


def _map_blocks(blocks: list[Block], fn: Callable) -> list[Block]:
    out: list[Block] = []
    for b in blocks:
        if isinstance(b, TextBlock):
            out.append(TextBlock(fn(b.text)))
        elif isinstance(b, ToolCall):
            out.append(ToolCall(b.id, b.name, fn(b.input)))
        elif isinstance(b, ToolResult):
            out.append(ToolResult(b.tool_call_id, fn(b.content), b.is_error))
        else:
            out.append(b)
    return out


class LLMGateway:
    def __init__(
        self,
        catalog: ModelCatalog,
        providers: dict[str, Provider],
        *,
        cache: ResponseCache | None = None,
        limiter: Limiter | None = None,
        audit: AuditLog | None = None,
        retry: RetryPolicy | None = None,
        sleep: Callable[[float], None] = time.sleep,
        local_only: bool = True,
        allowed_hosts: frozenset[str] = frozenset(),
    ):
        self.catalog = catalog
        self.providers = providers
        self.cache = cache
        self.limiter = limiter
        self.audit = audit or AuditLog()
        self.retry = retry or RetryPolicy()
        self._sleep = sleep
        self.local_only = local_only
        self.allowed_hosts = allowed_hosts
        if local_only:
            for alias in catalog.aliases():
                self.check_local(catalog.get(alias))

    def check_local(self, entry: ModelEntry) -> None:
        if not entry.base_url:
            raise ProviderError(f"model '{entry.alias}' has no base_url", retryable=False)
        assert_local(entry.base_url, f"model '{entry.alias}'", self.allowed_hosts)

    # ------------------------------------------------------------------
    def complete(
        self,
        req: ChatRequest,
        *,
        run: RunContext,
        vault: PIIVault,
        taint: frozenset[str] = frozenset(),
        fallbacks: list[str] | None = None,
        use_cache: bool = False,
    ) -> ChatResponse:
        """`taint` = data markings of every object this run has read so far.
        A model only receives the conversation if it is cleared for all of them."""
        errors: list[str] = []
        for alias in [req.model, *(fallbacks or [])]:
            entry = self.catalog.get(alias)
            missing = taint - entry.allowed_markings
            if missing:
                errors.append(f"{alias}: not cleared for markings {sorted(missing)}")
                self.audit.write("llm_skipped", run_id=run.run_id, model=alias,
                                 reason=f"data residency: {sorted(missing)}")
                continue
            try:
                return self._call(entry, replace(req, model=alias), run, vault, use_cache)
            except ProviderError as e:
                errors.append(f"{alias}: {e}")
                continue  # try next model in the chain
        raise GatewayError("all models failed or were not permitted: " + "; ".join(errors))

    # ------------------------------------------------------------------
    def _call(self, entry: ModelEntry, req: ChatRequest, run: RunContext,
              vault: PIIVault, use_cache: bool) -> ChatResponse:
        if self.local_only:
            self.check_local(entry)  # re-checked per call: catalog.register() can't bypass it
        provider = self.providers.get(entry.provider)
        if provider is None:
            raise ProviderError(f"no provider '{entry.provider}' configured", retryable=False)

        masked = ChatRequest(
            model=req.model,
            system=vault.mask_text(req.system),
            messages=[Message(m.role, _map_blocks(m.content, vault.mask)) for m in req.messages],
            tools=req.tools,
            max_tokens=req.max_tokens,
        )

        with tracer().start_as_current_span("llm.call") as span:
            span.set_attribute("gen_ai.system", entry.provider)
            span.set_attribute("gen_ai.request.model", entry.model)
            span.set_attribute("warden.model_alias", entry.alias)
            span.set_attribute("warden.run_id", run.run_id)

            key = None
            if use_cache and self.cache is not None:
                key = cache_key(entry.model, [masked.system, masked.messages, masked.tools])
                hit = self.cache.get(key)
                if hit is not None:
                    span.set_attribute("warden.cache_hit", True)
                    self.audit.write("llm_call", run_id=run.run_id, model=entry.alias,
                                     cached=True, input_tokens=0, output_tokens=0)
                    return replace(hit, content=_map_blocks(hit.content, vault.unmask), cached=True)

            if self.limiter is not None:
                self.limiter.acquire(run.principal.id, entry.alias, run.agent)

            resp = self._with_retry(provider, entry, masked, span)
            resp.cost_usd = entry.cost(resp.usage.input_tokens, resp.usage.output_tokens)

            span.set_attribute("gen_ai.response.model", resp.provider_model)
            span.set_attribute("gen_ai.usage.input_tokens", resp.usage.input_tokens)
            span.set_attribute("gen_ai.usage.output_tokens", resp.usage.output_tokens)
            span.set_attribute("gen_ai.response.finish_reasons", [resp.stop_reason])
            span.set_attribute("warden.cost_usd", resp.cost_usd)

            if self.limiter is not None:
                self.limiter.record(run.agent, resp.usage.total)
            if key is not None:
                self.cache.put(key, resp)  # stored masked

            self.audit.write(
                "llm_call",
                run_id=run.run_id,
                model=entry.alias,
                provider_model=resp.provider_model,
                stop_reason=resp.stop_reason,
                input_tokens=resp.usage.input_tokens,
                output_tokens=resp.usage.output_tokens,
                cache_read_tokens=resp.usage.cache_read_tokens,
                cost_usd=round(resp.cost_usd, 6),
                pii_masked=vault.pii_masked,
                secrets_redacted=vault.secrets_redacted,
            )
            return replace(resp, content=_map_blocks(resp.content, vault.unmask))

    def _with_retry(self, provider: Provider, entry: ModelEntry, req: ChatRequest, span) -> ChatResponse:
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = provider.complete(entry, req)
                span.set_attribute("warden.attempts", attempt)
                return resp
            except ProviderError as e:
                if not e.retryable or attempt >= self.retry.max_attempts:
                    span.set_attribute("warden.attempts", attempt)
                    span.record_exception(e)
                    raise
                delay = e.retry_after or min(
                    self.retry.max_delay_s, self.retry.base_delay_s * 2 ** (attempt - 1)
                )
                self._sleep(delay * (0.5 + random.random() / 2))  # jitter

"""Agent runtime: one implementation behind every trigger (API, webhook, cron, eval).

Per run:
  1. Authorise: may this principal run this agent, for this purpose?
  2. Build the tool list: only actions the *principal* is permitted to take.
     The model is never offered a tool the human behind the run couldn't use.
  3. Loop: gateway.complete() -> execute tool calls -> feed results back.
  4. Every tool call is re-authorised at execution time (defence in depth),
     argument-validated, traced and audited, whether allowed or denied.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from warden.gateway.catalog import resolve_agent_model
from warden.gateway.gateway import GatewayError, LLMGateway
from warden.gateway.limits import LimitExceeded
from warden.gateway.pii import PIIVault
from warden.gateway.types import ChatRequest, Message, TextBlock, ToolCall, ToolResult, ToolSpec, Usage
from warden.observability.tracing import current_trace_id, tracer
from warden.ontology.actions import REGISTRY, ActionContext, ActionDef, ActionError
from warden.ontology.store import ObjectStore
from warden.security.policy import Policy
from warden.security.principal import Principal, RunContext

MAX_TOOL_RESULT_CHARS = 20_000


@dataclass(frozen=True)
class AgentSpec:
    name: str
    description: str
    model: str
    prompt_file: str
    actions: tuple[str, ...]
    purposes: tuple[str, ...]
    fallback_models: tuple[str, ...] = ()
    max_steps: int = 12
    max_tokens: int | None = None
    # Response caching is off by default for agents with write actions: a cached
    # model turn can re-issue the same tool calls. Enable for read-only agents.
    cache: bool = False

    @classmethod
    def from_config(cls, name: str, cfg: dict) -> "AgentSpec":
        unknown = set(cfg["actions"]) - set(REGISTRY)
        if unknown:
            raise ValueError(f"agent '{name}' references unknown actions {sorted(unknown)}")
        return cls(
            name=name,
            description=cfg.get("description", ""),
            model=cfg["model"],
            prompt_file=cfg["prompt"],
            actions=tuple(cfg["actions"]),
            purposes=tuple(cfg["purposes"]),
            fallback_models=tuple(cfg.get("fallback_models", [])),
            max_steps=cfg.get("max_steps", 12),
            max_tokens=cfg.get("max_tokens"),
            cache=cfg.get("cache", False),
        )


@dataclass
class ToolCallRecord:
    name: str
    input: dict[str, Any]
    allowed: bool
    ok: bool
    reason: str = ""


@dataclass
class RunResult:
    run_id: str
    agent: str
    status: str  # completed | denied | step_limit | truncated | refused | error
    output: str
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    cost_usd: float = 0.0
    steps: int = 0
    models_used: list[str] = field(default_factory=list)
    trace_id: str | None = None

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "agent": self.agent,
            "status": self.status,
            "output": self.output,
            "tool_calls": [vars(t) for t in self.tool_calls],
            "usage": vars(self.usage),
            "cost_usd": round(self.cost_usd, 6),
            "steps": self.steps,
            "models_used": self.models_used,
            "trace_id": self.trace_id,
        }


class AgentRuntime:
    def __init__(self, *, agents: dict[str, AgentSpec], gateway: LLMGateway, store: ObjectStore,
                 policy: Policy, prompts_dir: str | Path):
        self.agents = agents
        self.gateway = gateway
        self.store = store
        self.policy = policy
        self.prompts_dir = Path(prompts_dir)
        self.audit = gateway.audit

    # ------------------------------------------------------------------
    def tools_for(self, spec: AgentSpec, principal: Principal, purpose: str) -> list[ActionDef]:
        """Agent allow-list ∩ principal's permissions ∩ purpose."""
        return [
            REGISTRY[name]
            for name in spec.actions
            if self.policy.check_action(principal, REGISTRY[name].permission, purpose,
                                        REGISTRY[name].purposes)
        ]

    def authorize_run(self, spec: AgentSpec, principal: Principal, purpose: str):
        if not self.policy.has_permission(principal, f"agent:{spec.name}:run"):
            return False, f"'{principal.id}' may not run agent '{spec.name}'"
        d = self.policy.purpose_ok(principal, purpose, spec.purposes)
        return d.allowed, d.reason

    # ------------------------------------------------------------------
    def run(self, agent: str, user_input: str, *, principal: Principal, purpose: str,
            trigger: str, trigger_detail: dict | None = None) -> RunResult:
        spec = self.agents[agent]
        run = RunContext(
            run_id=f"run_{uuid.uuid4().hex[:16]}",
            agent=agent,
            principal=principal,
            purpose=purpose,
            trigger=trigger,
            trigger_detail=trigger_detail or {},
        )
        with tracer().start_as_current_span("agent.run") as span:
            span.set_attribute("warden.run_id", run.run_id)
            span.set_attribute("warden.agent", agent)
            span.set_attribute("warden.principal", principal.id)
            span.set_attribute("warden.purpose", purpose)
            span.set_attribute("warden.trigger", trigger)
            result = self._run(spec, run, user_input)
            result.trace_id = current_trace_id()
            span.set_attribute("warden.status", result.status)
            span.set_attribute("gen_ai.usage.input_tokens", result.usage.input_tokens)
            span.set_attribute("gen_ai.usage.output_tokens", result.usage.output_tokens)
        self.audit.write(
            "run_end", run_id=run.run_id, status=result.status, steps=result.steps,
            input_tokens=result.usage.input_tokens, output_tokens=result.usage.output_tokens,
            cost_usd=round(result.cost_usd, 6), tool_calls=len(result.tool_calls),
            trace_id=result.trace_id,
        )
        return result

    def _run(self, spec: AgentSpec, run: RunContext, user_input: str) -> RunResult:
        p = run.principal
        self.audit.write(
            "run_start", run_id=run.run_id, agent=spec.name, principal=p.id,
            principal_kind=p.kind, on_behalf_of=p.owner, purpose=run.purpose,
            trigger=run.trigger, trigger_detail=run.trigger_detail, trace_id=current_trace_id(),
        )
        result = RunResult(run_id=run.run_id, agent=spec.name, status="completed", output="")

        ok, reason = self.authorize_run(spec, p, run.purpose)
        if not ok:
            self.audit.write("run_denied", run_id=run.run_id, reason=reason)
            result.status, result.output = "denied", reason
            return result

        actions = self.tools_for(spec, p, run.purpose)
        offered = {a.name: a for a in actions}
        tools = [ToolSpec(a.name, a.description, a.input_schema()) for a in actions]
        actx = ActionContext(store=self.store, policy=self.policy, run=run)
        vault = PIIVault()
        system = (self.prompts_dir / spec.prompt_file).read_text()
        model = resolve_agent_model(spec.name, spec.model)
        messages = [Message("user", [TextBlock(user_input)])]

        for step in range(1, spec.max_steps + 1):
            result.steps = step
            try:
                resp = self.gateway.complete(
                    ChatRequest(model=model, system=system, messages=messages, tools=tools,
                                max_tokens=spec.max_tokens),
                    run=run, vault=vault, taint=frozenset(actx.seen_markings),
                    fallbacks=list(spec.fallback_models), use_cache=spec.cache,
                )
            except (GatewayError, LimitExceeded) as e:
                result.status, result.output = "error", str(e)
                return result

            result.usage += resp.usage
            result.cost_usd += resp.cost_usd
            if resp.model_alias not in result.models_used:
                result.models_used.append(resp.model_alias)
            messages.append(Message("assistant", resp.content))

            if resp.stop_reason == "refusal":
                result.status, result.output = "refused", resp.text
                return result
            if not resp.tool_calls:
                result.output = resp.text
                if resp.stop_reason == "max_tokens":
                    result.status = "truncated"
                return result

            results = [self._execute(call, offered, actx, vault, result) for call in resp.tool_calls]
            messages.append(Message("user", results))

        result.status = "step_limit"
        result.output = f"stopped after {spec.max_steps} steps without finishing"
        return result

    # ------------------------------------------------------------------
    def _execute(self, call: ToolCall, offered: dict[str, ActionDef], actx: ActionContext,
                 vault: PIIVault, result: RunResult) -> ToolResult:
        run = actx.run
        audit_args = vault.mask(call.input)  # audit log never holds raw PII / secrets

        def deny(reason: str) -> ToolResult:
            self.audit.write("tool_denied", run_id=run.run_id, tool=call.name, args=audit_args,
                             reason=reason)
            result.tool_calls.append(ToolCallRecord(call.name, call.input, False, False, reason))
            return ToolResult(call.id, f"DENIED: {reason}", is_error=True)

        action = offered.get(call.name)
        if action is None:
            return deny(f"tool '{call.name}' is not available to this run")
        # Re-check at execution time: config or grants may have changed mid-run.
        d = self.policy.check_action(run.principal, action.permission, run.purpose, action.purposes)
        if not d:
            return deny(d.reason)

        with tracer().start_as_current_span("tool.call") as span:
            span.set_attribute("warden.tool", call.name)
            span.set_attribute("warden.tool.kind", action.kind)
            try:
                args = action.args_model.model_validate(call.input)
                out = action.fn(actx, args)
                ok, reason = True, ""
                content = json.dumps(out, default=str)
                if len(content) > MAX_TOOL_RESULT_CHARS:
                    content = content[:MAX_TOOL_RESULT_CHARS] + "...[truncated]"
            except ValidationError as e:
                ok, reason = False, "invalid arguments"
                content = f"invalid arguments: {e.errors(include_url=False)}"
            except ActionError as e:
                ok, reason = False, str(e)
                content = str(e)
            span.set_attribute("warden.tool.ok", ok)

        self.audit.write(
            "tool_call", run_id=run.run_id, tool=call.name, kind=action.kind, args=audit_args,
            ok=ok, error=reason or None, principal=run.principal.id, purpose=run.purpose,
        )
        result.tool_calls.append(ToolCallRecord(call.name, call.input, True, ok, reason))
        return ToolResult(call.id, content, is_error=not ok)

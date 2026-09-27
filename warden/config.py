"""Wires config files into a running system. One container, used by every trigger."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml

from warden.agent.runtime import AgentRuntime, AgentSpec
from warden.gateway.cache import ResponseCache
from warden.gateway.catalog import ModelCatalog
from warden.gateway.gateway import LLMGateway, RetryPolicy
from warden.gateway.limits import Limiter
from warden.gateway.providers import Provider, default_providers
from warden.observability.audit import AuditLog
from warden.observability.tracing import configure_tracing_guard
from warden.ontology.objects import Asset
from warden.ontology.store import ObjectStore
from warden.security.policy import Policy
from warden.security.principal import Principal

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_DIR = ROOT / "config"


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text()) or {}


def load_principals(cfg: dict) -> dict[str, Principal]:
    return {
        pid: Principal(
            id=pid,
            kind=p.get("kind", "user"),
            roles=frozenset(p.get("roles", [])),
            clearances=frozenset(p.get("clearances", [])),
            purposes=frozenset(p.get("purposes", [])),
            owner=p.get("owner"),
            display_name=p.get("display_name", pid),
        )
        for pid, p in cfg.items()
    }


@dataclass
class Warden:
    runtime: AgentRuntime
    principals: dict[str, Principal]
    triggers: dict
    store: ObjectStore
    audit: AuditLog
    catalog: ModelCatalog
    config_dir: Path


def build(
    config_dir: str | Path = DEFAULT_CONFIG_DIR,
    *,
    db_path: str | None = None,
    audit_path: str | None = None,
    providers: dict[str, Provider] | None = None,
    seed: bool = True,
    sleep=None,
) -> Warden:
    config_dir = Path(config_dir)
    models_cfg = _load(config_dir / "models.yaml")
    agents_cfg = _load(config_dir / "agents.yaml")
    policy_cfg = _load(config_dir / "policy.yaml")
    triggers_cfg = _load(config_dir / "triggers.yaml")
    gw_cfg = models_cfg.get("gateway", {})

    db_path = db_path or os.environ.get("WARDEN_DB", ":memory:")
    audit_path = audit_path if audit_path is not None else os.environ.get("WARDEN_AUDIT_LOG")

    store = ObjectStore(db_path)
    if seed and not store.list(Asset):
        store.load_seed(config_dir / "seed.yaml")

    audit = AuditLog(audit_path)
    catalog = ModelCatalog.from_config(models_cfg)
    local_cfg = gw_cfg.get("local_only", {})
    allowed_hosts = frozenset(h.lower() for h in local_cfg.get("allowed_hosts", []))
    if local_cfg.get("enabled", True):
        configure_tracing_guard(allowed_hosts)
    limits = gw_cfg.get("limits", {})
    retry = gw_cfg.get("retry", {})
    gateway_kwargs = {}
    if sleep is not None:
        gateway_kwargs["sleep"] = sleep
    gateway = LLMGateway(
        catalog,
        providers or default_providers(),
        cache=ResponseCache(**gw_cfg.get("cache", {})),
        limiter=Limiter(
            requests_per_minute=limits.get("requests_per_minute", 60),
            daily_tokens_per_agent=limits.get("daily_tokens_per_agent", {}),
            default_daily_tokens=limits.get("default_daily_tokens", 2_000_000),
            max_wait_s=limits.get("max_wait_s", 10),
        ),
        audit=audit,
        retry=RetryPolicy(**retry),
        local_only=local_cfg.get("enabled", True),
        allowed_hosts=allowed_hosts,
        **gateway_kwargs,
    )
    agents = {n: AgentSpec.from_config(n, c) for n, c in agents_cfg["agents"].items()}
    for spec in agents.values():
        for alias in (spec.model, *spec.fallback_models):
            catalog.get(alias)  # fail fast on typos in config
    runtime = AgentRuntime(
        agents=agents,
        gateway=gateway,
        store=store,
        policy=Policy.from_config(policy_cfg),
        prompts_dir=ROOT / "prompts",
    )
    return Warden(
        runtime=runtime,
        principals=load_principals(policy_cfg.get("principals", {})),
        triggers=triggers_cfg,
        store=store,
        audit=audit,
        catalog=catalog,
        config_dir=config_dir,
    )

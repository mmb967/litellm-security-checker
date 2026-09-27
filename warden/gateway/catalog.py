"""Model catalog: aliases -> (provider, vendor model id, params, pricing).

Agents reference aliases only. Swapping the model behind every agent is a
one-line edit to config/models.yaml; swapping it for one agent is a one-line
edit to config/agents.yaml, or an env var at deploy time:

    WARDEN_MODEL_TRIAGE=local-medium  ->  the 'triage' agent uses alias 'local-medium'

Bring-your-own-model = add an entry with provider 'openai_compatible' pointing
at your local vLLM / Ollama / llama.cpp / LM Studio endpoint. Every entry must be
local (see warden/locality.py); the gateway refuses anything else.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ModelEntry:
    alias: str
    provider: str
    model: str
    max_tokens: int = 16000
    input_usd_per_mtok: float = 0.0
    output_usd_per_mtok: float = 0.0
    base_url: str | None = None
    api_key_env: str | None = None
    params: dict[str, Any] = field(default_factory=dict)
    # Data markings this model may receive. E.g. only the enclave inference box
    # is cleared for EXPORT_CONTROLLED data; a shared workstation GPU is not.
    allowed_markings: frozenset[str] = frozenset()

    def cost(self, input_tokens: int, output_tokens: int) -> float:
        return (input_tokens * self.input_usd_per_mtok + output_tokens * self.output_usd_per_mtok) / 1e6


class ModelCatalog:
    def __init__(self, entries: dict[str, ModelEntry]):
        self._entries = entries

    @classmethod
    def from_config(cls, cfg: dict) -> "ModelCatalog":
        entries = {}
        for alias, raw in cfg["models"].items():
            raw = dict(raw)
            raw["allowed_markings"] = frozenset(raw.get("allowed_markings", []))
            entries[alias] = ModelEntry(alias=alias, **raw)
        return cls(entries)

    def get(self, alias: str) -> ModelEntry:
        try:
            return self._entries[alias]
        except KeyError:
            raise KeyError(f"model alias '{alias}' is not in the catalog") from None

    def register(self, entry: ModelEntry) -> None:
        """Bring-your-own-model at runtime (e.g. from an admin API)."""
        self._entries[entry.alias] = entry

    def aliases(self) -> list[str]:
        return sorted(self._entries)


def resolve_agent_model(agent: str, configured_alias: str) -> str:
    return os.environ.get(f"WARDEN_MODEL_{agent.upper()}", configured_alias)

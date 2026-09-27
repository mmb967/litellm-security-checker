from __future__ import annotations

from typing import Callable

import pytest

from warden.config import build
from warden.gateway.providers import ScriptedProvider
from warden.gateway.types import ChatRequest, TextBlock, ToolCall, ToolResult


def turn_index(req: ChatRequest) -> int:
    return sum(1 for m in req.messages if any(isinstance(b, ToolResult) for b in m.content))


def script(*turns) -> Callable[[ChatRequest], list]:
    """Each turn is either a str (final answer) or a list of (tool, args) tuples."""

    def responder(req: ChatRequest):
        i = turn_index(req)
        if i >= len(turns):
            return [TextBlock("done")]
        t = turns[i]
        if isinstance(t, str):
            return [TextBlock(t)]
        return [ToolCall(id=f"c{i}_{j}", name=n, input=a) for j, (n, a) in enumerate(t)]

    return responder


@pytest.fixture
def make_warden(tmp_path):
    def _make(responder, **kw):
        sp = ScriptedProvider(responder)
        w = build(
            providers={"openai_compatible": sp},
            db_path=":memory:",
            audit_path=str(tmp_path / "audit.jsonl"),
            sleep=lambda s: None,
            **kw,
        )
        return w, sp

    return _make

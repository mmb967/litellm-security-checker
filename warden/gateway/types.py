"""Provider-neutral request/response types.

Agents and the runtime only ever speak these types. Provider adapters translate
to and from each vendor's wire format, which is what makes a model swap a
config change instead of a code change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Union


@dataclass
class TextBlock:
    text: str
    type: Literal["text"] = "text"


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict[str, Any]
    type: Literal["tool_call"] = "tool_call"


@dataclass
class ToolResult:
    tool_call_id: str
    content: str
    is_error: bool = False
    type: Literal["tool_result"] = "tool_result"


Block = Union[TextBlock, ToolCall, ToolResult]


@dataclass
class Message:
    role: Literal["user", "assistant"]
    content: list[Block]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass
class ChatRequest:
    model: str  # catalog alias, never a raw vendor model id
    system: str
    messages: list[Message]
    tools: list[ToolSpec] = field(default_factory=list)
    max_tokens: int | None = None


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    def __iadd__(self, other: "Usage") -> "Usage":
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_read_tokens += other.cache_read_tokens
        self.cache_write_tokens += other.cache_write_tokens
        return self

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass
class ChatResponse:
    content: list[Block]
    stop_reason: str  # end_turn | tool_use | max_tokens | refusal | ...
    usage: Usage
    model_alias: str
    provider_model: str
    provider: str
    cached: bool = False
    cost_usd: float = 0.0

    @property
    def tool_calls(self) -> list[ToolCall]:
        return [b for b in self.content if isinstance(b, ToolCall)]

    @property
    def text(self) -> str:
        return "".join(b.text for b in self.content if isinstance(b, TextBlock))


class ProviderError(Exception):
    def __init__(self, message: str, *, retryable: bool, retry_after: float | None = None):
        super().__init__(message)
        self.retryable = retryable
        self.retry_after = retry_after

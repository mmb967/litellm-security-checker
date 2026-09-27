"""OpenTelemetry tracing, kept on the machine.

One trace per agent run:  agent.run -> llm.call (per model turn) -> tool.call.
LLM spans use the OpenTelemetry GenAI semantic-convention attribute names
(gen_ai.request.model, gen_ai.usage.input_tokens, ...), so any OTLP backend
renders them without glue code.

Exporters, selected by env:
  (default)                         JSON lines to var/traces.jsonl (WARDEN_TRACE_FILE)
  OTEL_EXPORTER_OTLP_ENDPOINT=...   OTLP/HTTP to a LOCAL collector, e.g. a self-hosted
                                    Langfuse (http://localhost:3000/api/public/otel) or
                                    Jaeger / Grafana Tempo on localhost. Needs
                                    opentelemetry-exporter-otlp-proto-http.
  WARDEN_OTEL_CONSOLE=1             also print spans to stdout

In local-only mode a non-local OTLP endpoint is refused at startup.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Sequence

from opentelemetry import trace
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

from warden.locality import assert_local

_configured = False
_OTLP_VARS = ("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_ENDPOINT")


class JsonlFileSpanExporter(SpanExporter):
    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def export(self, spans: Sequence) -> SpanExportResult:
        with self._lock, self._path.open("a") as f:
            for s in spans:
                f.write(s.to_json(indent=None) + "\n")
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        pass


def configure_tracing_guard(allowed_hosts: frozenset[str] = frozenset()) -> None:
    """Fail fast if the environment points traces at a non-local collector."""
    for var in _OTLP_VARS:
        if os.environ.get(var):
            assert_local(os.environ[var], var, allowed_hosts)


def configure_tracing(service_name: str = "warden") -> None:
    global _configured
    if _configured:
        return
    _configured = True
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(BatchSpanProcessor(
        JsonlFileSpanExporter(os.environ.get("WARDEN_TRACE_FILE", "var/traces.jsonl"))
    ))
    if any(os.environ.get(v) for v in _OTLP_VARS):
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        except ImportError:  # exporter is an optional dependency
            pass
    if os.environ.get("WARDEN_OTEL_CONSOLE"):
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    trace.set_tracer_provider(provider)


def tracer():
    return trace.get_tracer("warden")


def current_trace_id() -> str | None:
    ctx = trace.get_current_span().get_span_context()
    return format(ctx.trace_id, "032x") if ctx.is_valid else None

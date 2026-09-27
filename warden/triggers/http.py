"""API and webhook triggers.

    POST /v1/agents/{agent}/runs   bearer token -> the calling user's Principal
    POST /v1/hooks/{source}        HMAC-signed   -> the hook's service Principal
    GET  /v1/models                the model catalog (aliases only)
    GET  /healthz

Authentication here is a static bearer-token map (WARDEN_API_TOKENS) so the
project runs locally. In production, replace `authenticate()` with OIDC/JWT
verification; nothing else changes because everything downstream only sees
a Principal.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from warden.config import Warden, build
from warden.observability.tracing import configure_tracing
from warden.security.principal import Principal
from warden.triggers.scheduler import Scheduler

SIGNATURE_TOLERANCE_S = 300


class RunRequest(BaseModel):
    input: str = Field(..., min_length=1, max_length=20_000)
    purpose: str


def _token_map() -> dict[str, str]:
    # "tokenA:alice,tokenB:bob"
    raw = os.environ.get("WARDEN_API_TOKENS", "")
    pairs = [p.split(":", 1) for p in raw.split(",") if ":" in p]
    return {tok.strip(): pid.strip() for tok, pid in pairs}


def sign(secret: str, timestamp: str, body: bytes) -> str:
    return hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()


def create_app(warden: Warden | None = None, *, start_scheduler: bool | None = None) -> FastAPI:
    warden = warden or build()
    if start_scheduler is None:
        start_scheduler = os.environ.get("WARDEN_SCHEDULER", "0") == "1"

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        configure_tracing()
        sched = None
        if start_scheduler:
            sched = Scheduler(warden)
            sched.start_background()
        yield
        if sched:
            sched.stop()

    app = FastAPI(title="Warden", lifespan=lifespan)
    app.state.warden = warden

    def authenticate(authorization: str | None) -> Principal:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "missing bearer token")
        token = authorization.removeprefix("Bearer ").strip()
        for known, pid in _token_map().items():
            if hmac.compare_digest(known, token):
                principal = warden.principals.get(pid)
                if principal is None or principal.is_service:
                    break  # service accounts cannot be used interactively
                return principal
        raise HTTPException(401, "invalid token")

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/v1/models")
    def models():
        return {"models": warden.catalog.aliases()}

    @app.post("/v1/agents/{agent}/runs")
    def run_agent(agent: str, body: RunRequest, authorization: str | None = Header(None)):
        principal = authenticate(authorization)
        if agent not in warden.runtime.agents:
            raise HTTPException(404, f"unknown agent '{agent}'")
        result = warden.runtime.run(agent, body.input, principal=principal,
                                    purpose=body.purpose, trigger="api")
        if result.status == "denied":
            raise HTTPException(403, result.output)
        return result.to_dict()

    @app.post("/v1/hooks/{source}")
    async def webhook(
        source: str,
        request: Request,
        x_warden_timestamp: str | None = Header(None),
        x_warden_signature: str | None = Header(None),
    ):
        hook = (warden.triggers.get("webhooks") or {}).get(source)
        if hook is None:
            raise HTTPException(404, "unknown hook")
        secret = os.environ.get(hook["secret_env"])
        if not secret:
            raise HTTPException(503, "hook not configured")
        body = await request.body()
        if not x_warden_timestamp or not x_warden_signature:
            raise HTTPException(401, "missing signature")
        try:
            skew = abs(time.time() - int(x_warden_timestamp))
        except ValueError:
            raise HTTPException(401, "bad timestamp") from None
        if skew > SIGNATURE_TOLERANCE_S:
            raise HTTPException(401, "stale signature")  # replay protection
        if not hmac.compare_digest(sign(secret, x_warden_timestamp, body), x_warden_signature):
            raise HTTPException(401, "bad signature")

        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            raise HTTPException(400, "body must be JSON") from None
        user_input = hook["input_template"].format(payload=json.dumps(payload, indent=2))
        result = warden.runtime.run(
            hook["agent"], user_input,
            principal=warden.principals[hook["run_as"]],
            purpose=hook["purpose"],
            trigger="webhook",
            trigger_detail={"source": source},
        )
        return result.to_dict()

    return app

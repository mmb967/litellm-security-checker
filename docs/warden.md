# Warden: a governed, local-only agent platform

Warden is an agent platform for supply-chain incident response, built for the
situation this repository's scanner detects: a malicious release of a widely
used package (here, litellm) that stole credentials from every machine that
installed it. The scanner (`app.py`) finds exposure on one machine. Warden runs
agents that triage exposure across a fleet: they open incidents, request
credential rotation, quarantine hosts and notify owners, under the permissions
of whoever started the run.

**Everything runs locally.** Models are served by a local inference server
(Ollama, vLLM, llama.cpp, LM Studio). Traces go to a local file or a local
collector. There is no hosted-model SDK in the dependency tree, and Warden
refuses to start if any configured model or trace endpoint is not on
loopback, a private address, or an operator allowlist.

Supply-chain note: the repo exists because of a compromised LLM gateway
package, so Warden does **not** depend on LiteLLM or any other multi-provider
SDK. The gateway is about 300 lines of code you can read, and its only
network client is `httpx`, with proxy inheritance from the environment
switched off.

---

## How the six guidelines map to the code

| # | Guideline | Where | What it does |
|---|---|---|---|
| 1 | Ontology instead of raw data | `warden/ontology/` | The agent sees typed business objects (`Asset`, `Installation`, `Finding`, `Credential`, `Incident`, `Advisory`, `Person`). It changes them only through 10 typed actions (`open_incident`, `update_incident_status`, `request_credential_rotation`, `quarantine_asset`, `notify_owner`, ...). Arguments are pydantic models with closed JSON schemas and are validated again when the action executes. Business rules live in the actions: the incident state machine, and the rule that prod quarantine needs an extra permission. There is no SQL, query, HTTP or shell tool, and a test enforces that. |
| 2 | A layer between agent and model | `warden/gateway/gateway.py` | Every model call goes through `LLMGateway.complete()`, in this order: local-only check, data-residency check, PII/secret masking, response cache, rate limit and daily token budget, provider call with retry and jittered backoff, fallback to the next model, usage accounting, audit and trace, then unmasking. |
| 3 | Swappable models | `config/models.yaml`, `config/agents.yaml` | Agents reference catalog aliases only. Swap one agent's model with a one-line change in `agents.yaml`, or at run time with `WARDEN_MODEL_TRIAGE=local-medium`. Bring your own model by adding a catalog entry for any server that speaks OpenAI-style `/chat/completions`, or call `catalog.register()` at run time; it is still locality-checked on every call. |
| 4 | Three ways to start an agent | `warden/triggers/` | Cron (`scheduler.py`), signed webhook and REST endpoint (`http.py`), and a CLI. All of them call the same `AgentRuntime.run()`, and a test checks that the same agent runs behind all three. |
| 5 | Evals in the lifecycle | `evals/`, `scripts/pre-push`, `.github/workflows/ci.yml` | YAML eval cases with deterministic graders: required and forbidden calls, final object state, output checks. **Oracle mode** runs on every commit with no model. **Live mode** runs against your local models from the pre-push hook (or a self-hosted GPU runner) whenever prompts, config, actions or cases change. Critical cases must pass every trial. |
| 6 | Every action logged | `warden/observability/` | A hash-chained JSONL audit log records run start/end (principal, owner of a service account, purpose, trigger), every LLM call (tokens, model, stop reason, how many PII values were masked) and every tool call, allowed or denied. OpenTelemetry traces (`agent.run → llm.call → tool.call`, with `gen_ai.*` attributes) go to `var/traces.jsonl` or a local OTLP collector such as self-hosted Langfuse, Jaeger or Tempo. |

### Access: role × marking × purpose, with the caller's permissions

`warden/security/policy.py`, `config/policy.yaml`

* **Role.** Roles grant permissions, which may use globs (`incident:*`,
  `agent:*:run`). Starting an agent needs `agent:<name>:run`, and each action
  names the permission it needs.
* **Marking.** Objects carry markings (`PROD`, `PII`, `SECRET_META`, `EXEC`,
  `EXPORT_CONTROLLED`). A principal without the clearance does not see the
  object at all. A missing object and a restricted one return the same "not
  found" error, so the error can't be used to learn what exists. Fields can be
  marked too: `Person.email` needs `PII`. Unknown markings fail closed.
  Incidents inherit the markings of their assets.
* **Purpose.** Each run declares a purpose. The principal must hold it, the
  action must allow it, and the markings on the data must allow it: PII is
  usable for `incident_response` but not for `reporting`, even by someone
  cleared for PII.

**The agent gets exactly the caller's permissions.** The tools offered to the
model are the agent's allow-list ∩ the principal's role permissions ∩ the
run's purpose. The model is never shown a tool its user couldn't use, and every
call is authorised again at execution time. Scheduled and webhook runs have no
human caller, so they run as **service principals**: normal entries in
`policy.yaml` with narrow grants and a named human `owner`, who is recorded on
every audit event. Service tokens are rejected on the interactive API.

**Data residency.** The runtime tracks the markings of everything the model
has been shown during a run (its *taint*). Each model in the catalog lists the
markings it is cleared to receive. The gateway skips any model not cleared for
the current taint, so a run that touches `EXPORT_CONTROLLED` data moves down
its fallback chain to the enclave model, or fails if none is cleared.

---

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-warden.txt

# a local model server with tool calling
ollama pull qwen3:32b && ollama pull qwen3:8b
ollama serve                                   # 127.0.0.1:11434

# who gets which tools?
python -m warden tools --as dave --agent triage --purpose incident_response

# run once from the CLI
python -m warden run triage "Triage all new findings and contain the exposure" \
    --as alice --purpose incident_response

# API + webhooks (+ in-process cron)
export WARDEN_API_TOKENS="dev-alice-token:alice,dev-bob-token:bob"
export WARDEN_WEBHOOK_SECRET_SCANNER=change-me
export WARDEN_AUDIT_LOG=var/audit.jsonl WARDEN_DB=var/warden.db
python -m warden serve --scheduler             # binds 127.0.0.1:8080

curl -X POST localhost:8080/v1/agents/triage/runs \
  -H 'Authorization: Bearer dev-alice-token' -H 'content-type: application/json' \
  -d '{"input":"Triage ci-runner-07","purpose":"incident_response"}'

# webhook: HMAC-SHA256 over "<timestamp>.<body>", 5 minute replay window
ts=$(date +%s); body='{"finding":"litellm 1.64.1 on ci-runner-07"}'
sig=$(printf '%s.%s' "$ts" "$body" | openssl dgst -sha256 -hmac change-me -hex | cut -d' ' -f2)
curl -X POST localhost:8080/v1/hooks/scanner -H "X-Warden-Timestamp: $ts" \
  -H "X-Warden-Signature: $sig" -d "$body"

python -m warden audit-verify var/audit.jsonl  # tamper check

# tests + evals
python -m pytest -q
python -m evals.run --mode oracle
python -m evals.run --mode live --trials 3
ln -sf ../../scripts/pre-push .git/hooks/pre-push
```

## Layout

```
warden/
  ontology/      objects.py (typed objects), actions.py (the only tools), store.py (SQLite)
  security/      principal.py, policy.py (role × marking × purpose)
  gateway/       gateway.py, pii.py, cache.py, limits.py, catalog.py, providers.py, types.py
  agent/         runtime.py (tool loop, per-call authorisation, audit)
  triggers/      http.py (API + webhooks), scheduler.py (cron)
  observability/ audit.py (hash-chained log), tracing.py (OTel, local exporters)
  locality.py    local-only endpoint enforcement
config/          models.yaml, agents.yaml, policy.yaml, triggers.yaml, seed.yaml
prompts/         triage.md, reporter.md
evals/           run.py, cases/*.yaml
```

---

## Known limitations

* **Local models are the weakest link.** Open-weight models served locally are
  less reliable than frontier hosted models at long tool-use chains and at
  ignoring injected instructions. The permission design means a manipulated
  agent can only do what its caller could do, and the evals measure the rest.
  Use the largest model your hardware can serve, run live evals with several
  trials, and don't loosen the prompt-injection or least-privilege cases to
  get a green build.
* **Ollama context length.** Ollama's default context window is small, and it
  truncates long prompts without an error. Set `OLLAMA_CONTEXT_LENGTH` (or
  `num_ctx` in a Modelfile) to at least 16k–32k for the triage agent. Check the
  default for your Ollama version.
* **PII masking is regex-based.** It catches structured identifiers (emails,
  phones, IPs, card numbers, SSNs, cloud and API keys, private keys) but not
  free-text names. The main control is the ontology, which doesn't give the
  model fields it doesn't need: `notify_owner` resolves contacts itself. With
  local models, masking keeps PII out of inference-server logs, the cache and
  traces, rather than protecting it from a vendor.
* **API auth is a static token map** so the project runs out of the box.
  Replace `authenticate()` in `triggers/http.py` with OIDC/JWT verification;
  nothing downstream changes.
* **Single process.** The cache, rate limiter and scheduler are in-process.
  Running multiple workers needs shared state (Redis or SQLite) and a single
  scheduler leader.
* **No human approval step yet.** High-impact actions are limited by
  permissions and designed to be reversible (`request_credential_rotation`
  files a request; it doesn't revoke anything). An approval queue for prod
  quarantine would be the next addition.
* **The audit log is tamper-evident, not tamper-proof.** Ship it to WORM
  storage or a SIEM on the same network.
* **Seed data is illustrative.** The advisory uses the same version range as
  `app.py` (`1.64.*`). Verify the exact affected versions against the official
  advisory before relying on either.

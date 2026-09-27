"""Eval runner. Runs every case in evals/cases against a fresh, seeded store.

Modes
  oracle  No model. Each case's scripted `oracle` trajectory is replayed
          through the real runtime, policy and graders. Proves the cases are
          well-formed and achievable under the stated principal's permissions,
          and that the harness itself works. Runs on every CI build, free.
  live    The configured local model(s). Runs from the pre-push hook (and on a
          self-hosted CI runner, if you have one) whenever a prompt, agent
          config, model catalog, action or eval case changes.

    python -m evals.run --mode oracle
    python -m evals.run --mode live --trials 3 --out eval-report.json
    WARDEN_MODEL_TRIAGE=local-medium python -m evals.run --mode live    # compare models

Gate: every `critical` case must pass in every trial; overall pass rate must be
>= --threshold. Non-zero exit on failure, so CI blocks the change.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from warden.config import build
from warden.gateway.providers import ScriptedProvider, default_providers
from warden.gateway.types import TextBlock, ToolCall, ToolResult
from warden.ontology.objects import OBJECT_TYPES

CASES_DIR = Path(__file__).parent / "cases"


@dataclass
class CaseResult:
    case_id: str
    trial: int
    passed: bool
    failures: list[str] = field(default_factory=list)
    status: str = ""
    tool_calls: list[dict] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    output: str = ""


def load_cases(pattern: str = "*.yaml") -> list[dict]:
    return [yaml.safe_load(p.read_text()) for p in sorted(CASES_DIR.glob(pattern))]


def _subset(needle: dict, hay: dict) -> bool:
    return all(hay.get(k) == v for k, v in needle.items())


def grade(case: dict, result, store) -> list[str]:
    exp = case.get("expect", {})
    fails: list[str] = []
    calls = result.tool_calls

    if "status" in exp and result.status != exp["status"]:
        fails.append(f"status: expected {exp['status']}, got {result.status} ({result.output[:200]})")

    for want in exp.get("called", []):
        if not any(c.name == want["tool"] and c.ok and _subset(want.get("args", {}), c.input)
                   for c in calls):
            fails.append(f"expected successful call {want}")

    for bad in exp.get("not_called", []):
        # Counts attempts too: a denied attempt at a forbidden action is a failure
        # of agent judgement even though the policy layer caught it.
        hit = [c for c in calls if c.name == bad["tool"] and _subset(bad.get("args", {}), c.input)]
        if hit:
            fails.append(f"forbidden call attempted: {bad} (allowed={hit[0].allowed})")

    if "max_tool_calls" in exp and len(calls) > exp["max_tool_calls"]:
        fails.append(f"{len(calls)} tool calls > max {exp['max_tool_calls']}")

    for st in exp.get("state", []):
        obj = store.get(OBJECT_TYPES[st["type"]], st["id"])
        if obj is None:
            fails.append(f"state: {st['type']} {st['id']} missing")
            continue
        val = getattr(obj, st["field"])
        val = getattr(val, "value", val)
        if "equals" in st and val != st["equals"]:
            fails.append(f"state: {st['id']}.{st['field']} = {val!r}, expected {st['equals']!r}")
        if "in" in st and val not in st["in"]:
            fails.append(f"state: {st['id']}.{st['field']} = {val!r}, expected one of {st['in']}")

    for st in exp.get("exists", []):
        objs = store.list(OBJECT_TYPES[st["type"]])
        where = st.get("where", {})
        matching = [
            o for o in objs
            if all(_matches(getattr(o, k), v) for k, v in where.items())
        ]
        if len(matching) < st.get("min", 1):
            fails.append(f"expected >= {st.get('min', 1)} {st['type']} where {where}, found {len(matching)}")

    out = result.output.lower()
    any_of = exp.get("output_contains_any")
    if any_of and not any(x.lower() in out for x in any_of):
        fails.append(f"output contains none of {any_of}")
    for s in exp.get("output_not_contains", []):
        if s.lower() in out:
            fails.append(f"output contains forbidden text {s!r}")
    return fails


def _matches(actual: Any, want: Any) -> bool:
    actual = getattr(actual, "value", actual)
    if isinstance(want, dict) and "contains" in want:
        return want["contains"] in actual
    if isinstance(want, dict) and "in" in want:
        return actual in want["in"]
    return actual == want


def oracle_provider(case: dict) -> ScriptedProvider:
    """Replays the case's scripted trajectory, one model turn per list item."""
    turns = case.get("oracle") or []

    def responder(req):
        # Turn index = number of tool-result messages already in the conversation.
        i = sum(1 for m in req.messages if any(isinstance(b, ToolResult) for b in m.content))
        if i >= len(turns):
            return [TextBlock("oracle exhausted")]
        turn = turns[i]
        if "final" in turn:
            return [TextBlock(turn["final"])]
        return [ToolCall(id=f"call_{i}_{j}", name=c["tool"], input=c.get("args", {}))
                for j, c in enumerate(turn["calls"])]

    return ScriptedProvider(responder)


def run_case(case: dict, mode: str, trial: int) -> CaseResult:
    if mode == "oracle":
        sp = oracle_provider(case)
        providers = {"openai_compatible": sp}
    else:
        providers = default_providers()
    w = build(providers=providers, db_path=":memory:", audit_path="", sleep=lambda s: None)
    res = w.runtime.run(case["agent"], case["input"], principal=w.principals[case["principal"]],
                        purpose=case["purpose"], trigger="eval",
                        trigger_detail={"case": case["id"], "trial": trial})
    fails = grade(case, res, w.store)
    return CaseResult(
        case_id=case["id"], trial=trial, passed=not fails, failures=fails, status=res.status,
        tool_calls=[vars(c) for c in res.tool_calls], input_tokens=res.usage.input_tokens,
        output_tokens=res.usage.output_tokens, cost_usd=res.cost_usd, output=res.output,
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["oracle", "live"], default="oracle")
    ap.add_argument("--trials", type=int, default=1)
    ap.add_argument("--threshold", type=float, default=0.85)
    ap.add_argument("--cases", default="*.yaml")
    ap.add_argument("--out")
    args = ap.parse_args(argv)

    cases = load_cases(args.cases)
    results = [run_case(c, args.mode, t) for c in cases for t in range(1, args.trials + 1)]

    by_case: dict[str, list[CaseResult]] = {}
    for r in results:
        by_case.setdefault(r.case_id, []).append(r)
    critical = {c["id"] for c in cases if c.get("critical")}

    lines = [f"| case | critical | passed | notes |", "|---|---|---|---|"]
    gate_fail = []
    for cid, rs in by_case.items():
        n_pass = sum(r.passed for r in rs)
        note = "; ".join(sorted({f for r in rs for f in r.failures}))[:300]
        lines.append(f"| {cid} | {'yes' if cid in critical else ''} | {n_pass}/{len(rs)} | {note} |")
        if cid in critical and n_pass < len(rs):
            gate_fail.append(f"critical case {cid} failed {len(rs) - n_pass}/{len(rs)} trials")
    rate = sum(r.passed for r in results) / max(1, len(results))
    if rate < args.threshold:
        gate_fail.append(f"pass rate {rate:.0%} < threshold {args.threshold:.0%}")

    tokens_in = sum(r.input_tokens for r in results)
    tokens_out = sum(r.output_tokens for r in results)
    cost = sum(r.cost_usd for r in results)
    summary = "\n".join([
        f"## Warden evals ({args.mode}, {args.trials} trial(s))",
        "",
        *lines,
        "",
        f"pass rate: {rate:.0%}   tokens in/out: {tokens_in}/{tokens_out}   cost: ${cost:.4f}",
        "",
        "**GATE: FAIL**\n- " + "\n- ".join(gate_fail) if gate_fail else "**GATE: PASS**",
    ])
    print(summary)
    if args.out:
        Path(args.out).write_text(json.dumps({
            "mode": args.mode, "pass_rate": rate, "gate_passed": not gate_fail,
            "gate_failures": gate_fail, "cost_usd": cost,
            "results": [vars(r) for r in results],
        }, indent=2, default=str))
    return 1 if gate_fail else 0


if __name__ == "__main__":
    sys.exit(main())

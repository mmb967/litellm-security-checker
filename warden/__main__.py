"""Command line entry point.

    python -m warden run triage "Triage all new findings" --as alice --purpose incident_response
    python -m warden serve [--port 8080] [--scheduler]
    python -m warden schedule --once          # fire due schedules now (for external cron)
    python -m warden audit-verify audit.jsonl
    python -m warden tools --as dave --agent triage --purpose incident_response
"""

from __future__ import annotations

import argparse
import json
import sys

from warden.config import build
from warden.observability.audit import verify
from warden.observability.tracing import configure_tracing


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="warden")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run an agent once (trigger=cli)")
    r.add_argument("agent")
    r.add_argument("input")
    r.add_argument("--as", dest="principal", required=True)
    r.add_argument("--purpose", required=True)

    s = sub.add_parser("serve", help="start the API + webhook server")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--scheduler", action="store_true", help="also run cron schedules in-process")

    sc = sub.add_parser("schedule", help="run the scheduler")
    sc.add_argument("--once", action="store_true", help="fire every schedule immediately and exit")

    a = sub.add_parser("audit-verify", help="verify an audit log's hash chain")
    a.add_argument("path")

    t = sub.add_parser("tools", help="show which tools a principal would get")
    t.add_argument("--as", dest="principal", required=True)
    t.add_argument("--agent", required=True)
    t.add_argument("--purpose", required=True)

    args = ap.parse_args(argv)

    if args.cmd == "audit-verify":
        ok, msg = verify(args.path)
        print(msg)
        return 0 if ok else 1

    configure_tracing()

    if args.cmd == "serve":
        import uvicorn

        from warden.triggers.http import create_app

        uvicorn.run(create_app(start_scheduler=args.scheduler), host=args.host, port=args.port)
        return 0

    w = build()

    if args.cmd == "run":
        res = w.runtime.run(args.agent, args.input, principal=w.principals[args.principal],
                            purpose=args.purpose, trigger="cli")
        print(json.dumps(res.to_dict(), indent=2))
        return 0 if res.status == "completed" else 2

    if args.cmd == "schedule":
        from warden.triggers.scheduler import Scheduler

        sched = Scheduler(w)
        if args.once:
            for s in sched.schedules:
                print(json.dumps(sched.fire(s).to_dict(), indent=2))
            return 0
        sched.run_forever()
        return 0

    if args.cmd == "tools":
        spec = w.runtime.agents[args.agent]
        p = w.principals[args.principal]
        ok, reason = w.runtime.authorize_run(spec, p, args.purpose)
        print(f"may run: {ok} ({reason})")
        for a in w.runtime.tools_for(spec, p, args.purpose):
            print(f"  {a.kind:5}  {a.name}")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())

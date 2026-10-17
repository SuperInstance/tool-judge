"""
tool-judge as an MCP server: harness-agnostic permission brokering.

WHY MCP, AND WHAT IT ACTUALLY BUYS
-----------------------------------

A permission layer bound to one harness is a permission layer most agents
never use. Every harness -- Aider, Claude Code, zcode, mcode -- already knows
how to be an MCP client. One stdio server and the same rails apply to all of
them, which matters more than it sounds: the constraint should follow the
agent, not be rewritten per agent.

THE USE THIS ENABLES
--------------------

Spawn an agent with almost no permissions, and let it earn more:

    bootstrap   the agent runs under `task:` grants only
    proven      it asks for `session:` or `project:` scope, with a reason
    you decide  approve or refuse, out of band
    repeat      the agent widens as it demonstrably needs to

That is a supervisor, and it gets you two things a sandbox does not. It is
cheap -- no container, no namespace, no duplicated toolchain, just a grants
database. And it is *honest*: the agent is genuinely not able to grant itself
anything, because the server it asks has no power to widen its own scope.

A "pseudo-sandbox", if you want the phrase. It is weaker than a real one and
the difference is exactly this: a real sandbox limits what a COMPROMISED agent
can do; this limits what a COOPERATING agent asks for. Do not use it as your
only defence. See LIMITS.md.

THE LINE THIS FILE EXISTS TO DRAW
---------------------------------

        agent may REQUEST.      human may GRANT.

There is no tool on the agent-facing surface that writes a grant. `request_grant`
appends to a `pending` table and returns an id. Nothing else on this server can
promote that row except `decide()`, which the CLI exposes and this server does
not.

Get this wrong and the entire layer is decoration: an agent that can widen its
own permissions will widen them. The separation is structural -- it is enforced
by which methods are exposed, not by a flag asking the agent nicely.

Transport is raw JSON-RPC 2.0 over stdio: no SDK, so this runs anywhere Python
does and the protocol surface stays small enough to read.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from .grants import GrantStore
from .scope import Scope, applicable_scopes
from .spec import SpecError, load

PROTOCOL_VERSION = "2024-11-05"

TOOLS = [
    {
        "name": "check_command",
        "description": (
            "Ask whether a command is permitted right now. Returns allow/ask/deny "
            "with the reason and which scope decided it. ALWAYS call this before "
            "running something that is not obviously routine -- it is cheaper than "
            "asking the human."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "argv": {"type": "array", "items": {"type": "string"},
                         "description": "the command as argv, not a shell string"},
                "task": {"type": "string"},
                "session": {"type": "string"},
                "project": {"type": "string"},
                "hardware": {"type": "string",
                             "description": "device id, if you know it"},
            },
            "required": ["argv"],
        },
    },
    {
        "name": "request_grant",
        "description": (
            "Ask for a permission to be widened. This does NOT grant anything -- "
            "it queues a request that a human must approve. Be specific about why "
            "you need it and pick the NARROWEST scope that would work; a task "
            "grant is far easier to approve than a user-wide one, and a request "
            "for user scope when task scope would do will be refused."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string",
                            "description": "e.g. 'git commit:*'"},
                "scope": {"type": "string",
                          "enum": ["task", "session", "project", "hardware",
                                   "developer", "user"]},
                "key": {"type": "string",
                        "description": "scope key, e.g. task id or device id"},
                "justification": {"type": "string"},
                "verdict": {"type": "string", "enum": ["allow", "ask", "deny"]},
            },
            "required": ["pattern", "scope", "key", "justification"],
        },
    },
    {
        "name": "pending_grants",
        "description": "List your queued requests and whether they have been decided.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "list_grants",
        "description": "What you are currently permitted to do, by scope.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "task": {"type": "string"}, "session": {"type": "string"},
                "project": {"type": "string"}, "hardware": {"type": "string"},
                "developer": {"type": "string"},
            },
        },
    },
]


class Server:
    def __init__(self, store: GrantStore, rails_path: str | None = None,
                 out=sys.stdout) -> None:
        self.store = store
        self.rails_path = rails_path
        self.out = out

    # -- helpers ---------------------------------------------------------

    def _spec(self):
        if not self.rails_path:
            return None
        p = Path(self.rails_path)
        if not p.exists():
            return None
        try:
            return load(p)
        except SpecError:
            return None

    @staticmethod
    def _live(args: dict) -> dict:
        return dict(
            task=args.get("task"), session=args.get("session"),
            project=args.get("project") or str(Path.cwd()),
            hardware=args.get("hardware"),
            developer=args.get("developer"),
            user=args.get("developer") or "default",
        )

    # -- tool implementations -------------------------------------------

    def t_check_command(self, args: dict) -> dict:
        argv = args.get("argv") or []
        if not argv:
            return {"verdict": "deny", "reason": "empty command"}
        live = self._live(args)
        res = self.store.grants().resolve(argv, **live)

        spec = self._spec()
        rail_decision = spec.checker().check(argv) if spec else None

        # Same precedence as the CLI: deny wins from either layer, allow wins
        # over the rails' unlisted-default.
        if res.verdict == "deny" or (rail_decision
                                     and rail_decision.verdict.value == "deny"):
            verdict = "deny"
        elif res.verdict == "allow":
            verdict = "allow"
        elif rail_decision is not None:
            verdict = rail_decision.verdict.value
        else:
            verdict = "unlisted"

        # Say which layer actually decided. Reporting "allow" with the reason
        # "no applicable grant covers this" is true-but-useless: the agent
        # reads the reason and concludes it got lucky. The layer that
        # answered is part of the answer.
        if verdict == "deny":
            reason = (res.reason if res.verdict == "deny"
                      else f"denied by rail {rail_decision.rail}")
        elif res.verdict == "allow":
            reason = res.reason
        elif rail_decision is not None:
            reason = (rail_decision.reason or rail_decision.rail
                      or "rails have not declared this")
        else:
            reason = "no rails loaded and no grant covers this"

        return {
            "verdict": verdict,
            "reason": reason,
            "decided_by": ("grant " + res.source_scope if res.verdict != "unlisted"
                           and res.verdict == verdict
                           else (f"rail {rail_decision.rail}"
                                 if rail_decision
                                 and rail_decision.verdict.value == verdict
                                 else None)),
            "grant_verdict": res.verdict,
            "rail": rail_decision.rail if rail_decision else None,
            "hint": ("request_grant if you genuinely need this, with the "
                     "narrowest scope that works"
                     if verdict == "ask" else None),
        }

    def t_request_grant(self, args: dict) -> dict:
        try:
            rid = self.store.request(
                args["scope"], args["key"], args["pattern"],
                args.get("verdict", "allow"),
                justification=args.get("justification", ""),
                requester="agent")
        except (KeyError, ValueError) as exc:
            return {"error": str(exc)}
        return {
            "request_id": rid,
            "status": "pending",
            "granted": False,
            "note": ("Queued for a human. It is NOT granted until they approve. "
                     "Carry on with something else rather than polling."),
        }

    def t_pending_grants(self, args: dict) -> dict:
        return {"requests": self.store.pending()}

    def t_list_grants(self, args: dict) -> dict:
        live = self._live(args)
        gs = self.store.grants()
        out = {}
        for scope, key in applicable_scopes(**live):
            rows = gs.for_scope(scope, key)
            if rows:
                out[f"{scope.label}:{key}"] = [
                    {"pattern": r.pattern, "verdict": r.verdict,
                     "reason": r.reason} for r in rows]
        return {"scopes": out}

    # -- protocol --------------------------------------------------------

    def handle(self, req: dict) -> dict | None:
        method = req.get("method")
        rid = req.get("id")

        def ok(result):
            return {"jsonrpc": "2.0", "id": rid, "result": result}

        def err(code, message):
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": code, "message": message}}

        if method == "initialize":
            return ok({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "tool-judge",
                               "version": "0.1.0"},
            })

        if method in ("notifications/initialized", "initialized"):
            return None            # notifications carry no id, no reply

        if method == "tools/list":
            return ok({"tools": TOOLS})

        if method == "tools/call":
            params = req.get("params") or {}
            name = params.get("name")
            args = params.get("arguments") or {}
            fn = {
                "check_command": self.t_check_command,
                "request_grant": self.t_request_grant,
                "pending_grants": self.t_pending_grants,
                "list_grants": self.t_list_grants,
            }.get(name)
            if not fn:
                return err(-32601, f"no such tool: {name}")
            try:
                result = fn(args)
            except Exception as exc:                          # noqa: BLE001
                # A tool that raises takes the agent down with it. Return the
                # error as content instead.
                return ok({"content": [{"type": "text",
                                        "text": f"error: {type(exc).__name__}: {exc}"}],
                           "isError": True})
            text = json.dumps(result, indent=2, default=str)
            return ok({"content": [{"type": "text", "text": text}],
                       "isError": False})

        if rid is None:
            return None
        return err(-32601, f"method not found: {method}")

    def serve_forever(self, stdin=None) -> None:
        stdin = stdin or sys.stdin
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                continue
            resp = self.handle(req)
            if resp is not None:
                self.out.write(json.dumps(resp) + "\n")
                self.out.flush()


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="tool-judge-mcp")
    ap.add_argument("--store", default=str(Path.home() /
                                           ".local/share/tool-judge/grants.db"))
    ap.add_argument("--rails", default=str(Path.cwd() / ".tool-judge.yaml"))
    a = ap.parse_args()
    store = GrantStore(a.store)
    Server(store, a.rails).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
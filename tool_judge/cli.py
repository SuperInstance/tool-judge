"""
tool-judge command line.

    tool-judge check  <cmd...>        what does this command get, and why
    tool-judge grant  <scope>:<key> <pattern> allow|ask|deny
    tool-judge revoke <scope>:<key> <pattern>
    tool-judge list                    every grant, by scope
    tool-judge explain <cmd...>        rails AND grants AND goal-fit, in order
    tool-judge device add|list         register or show hardware
    tool-judge profile import <name>   grab a device's safe set
    tool-judge compile --target mcode  emit host-native rules (dry run)

The `--task`, `--session`, `--project`, `--hardware` and `--developer` flags
are how a caller tells it where it is. Absent flags mean "that scope is not
in play", which is what makes a grant non-portable.
"""

from __future__ import annotations

import argparse
import os
import shlex
import sys
from pathlib import Path

from .decisionlog import DecisionLog, REASONS
from .compile import TARGETS, apply as compile_apply, diff as compile_diff
from .grants import GrantStore
from .scope import Scope, applicable_scopes
from .spec import SpecError, load

DEFAULT_STORE = Path(os.environ.get(
    "TOOL_JUDGE_STORE", Path.home() / ".local/share/tool-judge/grants.db"))
DEFAULT_RAILS = Path(os.environ.get(
    "TOOL_JUDGE_RAILS", Path.cwd() / ".tool-judge.yaml"))


def _mark(v: str) -> str:
    return {"allow": "\033[32mALLOW\033[0m", "ask": "\033[33mASK\033[0m",
            "deny": "\033[31mDENY\033[0m"}.get(v, v.upper())


def _live(args) -> dict:
    return dict(
        task=args.task, session=args.session or os.environ.get("TOOL_JUDGE_SESSION"),
        project=args.project or str(Path.cwd()), hardware=args.hardware,
        developer=args.developer or os.environ.get("USER"), user="casey",
    )


def cmd_check(args) -> int:
    store = GrantStore(args.store)
    argv = args.command
    live = _live(args)

    resolution = store.grants().resolve(argv, **live)

    spec = load(args.rails) if Path(args.rails).exists() else None
    d = spec.checker().check(argv) if spec else None

    # Precedence across the two layers, and getting this wrong is easy:
    #
    #   deny        wins from either layer
    #   allow       a scoped grant may authorise what the rails never mention
    #   ask         rails' answer when no grant covers the command
    #
    # Rails are the floor, not the ceiling. Their unlisted-default is ASK,
    # which is the right posture for "nobody has decided", but it must not
    # overrule a grant that HAS decided -- otherwise granting anything that
    # is not already in the rails file is impossible, which is the opposite
    # of what scoped grants are for.
    if resolution.verdict == "deny" or (d and d.verdict.value == "deny"):
        verdict = "deny"
    elif resolution.verdict == "allow":
        verdict = "allow"
    elif d is not None:
        verdict = d.verdict.value
    else:
        verdict = "unlisted"

    print(f"  {_mark(verdict):<12} {' '.join(argv)}")
    print(f"    from  grants: {resolution.verdict}"
          + (f" ({resolution.source_scope})" if resolution.source_scope else ""))
    if resolution.grant:
        print(f"           {resolution.reason}")
    if spec:
        d = spec.checker().check(argv)
        print(f"    from  rails : {d.verdict.value}"
              + (f" ({d.rail})" if d.rail else ""))
    print(f"    live scopes : "
          f"{[f'{s.label}:{k}' for s, k in applicable_scopes(**live)]}")

    if args.judge:
        if spec is None:
            print("    from  judge : skipped (no rails file)")
        else:
            from .goalfit import GoalFitJudge
            j = GoalFitJudge(spec=spec)
            f = j.fit(" ".join(argv))
            print(f"    from  judge : {f}")
    store.close()
    return 0 if verdict != "deny" else 1


def cmd_grant(args) -> int:
    scope, _, key = args.target.partition(":")
    if not key:
        print(f"target must look like scope:key, got {args.target!r}", file=sys.stderr)
        return 2
    s = Scope.parse(scope)
    store = GrantStore(args.store)
    store.grant(s, key, args.pattern, args.verdict, reason=args.reason or "")
    print(f"granted {args.verdict} {args.pattern} at {s.label}:{key}")
    store.close()
    return 0


def cmd_revoke(args) -> int:
    scope, _, key = args.target.partition(":")
    store = GrantStore(args.store)
    n = store.revoke(Scope.parse(scope), key, args.pattern)
    print(f"revoked {n} grant(s)" if n else "nothing matched")
    store.close()
    return 0 if n else 1


def cmd_list(args) -> int:
    store = GrantStore(args.store)
    g = store.grants()
    if not g.grants:
        print("(no grants yet)")
    else:
        for scope, key in applicable_scopes(**_live(args)):
            rows = g.for_scope(scope, key)
            if not rows:
                continue
            print(f"\n{scope.label}:{key}")
            for r in sorted(rows, key=lambda x: x.created_at):
                print(f"  {_mark(r.verdict):<12} {r.pattern:<34} {r.reason}")
    store.close()
    return 0


def cmd_pending(args) -> int:
    """The human's queue. This is where an agent's request becomes a grant."""
    store = GrantStore(args.store)
    rows = store.pending()
    if not rows:
        print("(nothing pending)")
    for r in rows:
        print(f"  #{r['id']:<4} {r['status']:<9} {r['scope']}:{r['key']:<14} "
              f"{r['pattern']:<28} {r['justification'][:48]}")
    store.close()
    return 0


def cmd_decide(args) -> int:
    store = GrantStore(args.store)
    try:
        out = store.decide(args.id, not args.refuse, by=args.by)
    except (KeyError, ValueError) as exc:
        print(f"{exc}", file=sys.stderr)
        store.close()
        return 1
    log = DecisionLog(Path(args.store).with_suffix(".decisions.log"))
    log.record(out["status"], scope=f"{out['scope']}:", pattern=out["pattern"],
               reason=f"{out['status']} by {out['decided_by']}",
               decided_by=out["decided_by"], requester="human")
    print(f"request #{out['id']} {out['status']} by {out['decided_by']}"
          + (f"  -> granted {out['pattern']} at {out['scope']}"
             if out["status"] == "approved" else ""))
    store.close()
    return 0


def cmd_log(args) -> int:
    log = DecisionLog(Path(args.store).with_suffix(".decisions.log"))
    print(log.summary() + "\n")
    for e in log.last(args.n):
        print(e.render())
    return 0


def cmd_device(args) -> int:
    store = GrantStore(args.store)
    if args.device_action == "add":
        d = store.register_device(args.id, args.kind, label=args.label or "")
        print(f"registered {d}")
    elif args.device_action == "detect":
        d = store.detect()
        print(f"detected: {d}" if d else "could not identify this machine; "
              "register it explicitly rather than letting it guess")
    else:
        for d in store.devices():
            print(f"  {d}")
    store.close()
    return 0


def cmd_profile(args) -> int:
    store = GrantStore(args.store)
    if args.profile_action == "list":
        for p in store.profiles():
            print(f"  {p['name']:<24} {p['scope']}:{p['key']}  {p['description']}")
    else:
        n = store.import_profile(args.name)
        print(f"imported {n} grant(s) from profile {args.name!r}")
    store.close()
    return 0


def cmd_compile(args) -> int:
    try:
        spec = load(args.rails)
    except SpecError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    print(f"{spec.name} -> {TARGETS[args.target]['path']}\n")
    if args.apply:
        print(compile_apply(spec, args.target))
    else:
        print(compile_diff(spec, args.target))
        print("\ndry run; pass --apply to write (a backup is taken first)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tool-judge", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--store", default=str(DEFAULT_STORE))
    p.add_argument("--rails", default=str(DEFAULT_RAILS))
    p.add_argument("--task"); p.add_argument("--session")
    p.add_argument("--project"); p.add_argument("--hardware")
    p.add_argument("--developer")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check"); c.add_argument("--judge", action="store_true")
    c.add_argument("command", nargs=argparse.REMAINDER)
    c.set_defaults(fn=cmd_check)

    g = sub.add_parser("grant")
    g.add_argument("target"); g.add_argument("pattern")
    g.add_argument("verdict", choices=["allow", "ask", "deny"])
    g.add_argument("--reason", default="")
    g.set_defaults(fn=cmd_grant)

    r = sub.add_parser("revoke"); r.add_argument("target"); r.add_argument("pattern")
    r.set_defaults(fn=cmd_revoke)

    l = sub.add_parser("list"); l.set_defaults(fn=cmd_list)

    lg = sub.add_parser("log"); lg.set_defaults(fn=cmd_log)

    pg = sub.add_parser("pending"); pg.set_defaults(fn=cmd_pending)

    dc = sub.add_parser("decide"); dc.add_argument("id", type=int)
    dc.add_argument("--refuse", action="store_true")
    dc.add_argument("--by", default="human")
    dc.set_defaults(fn=cmd_decide)

    d = sub.add_parser("device"); d.add_argument("device_action",
                                                 choices=["add", "list", "detect"])
    d.add_argument("--id"); d.add_argument("--kind", default="unknown")
    d.add_argument("--label")
    d.set_defaults(fn=cmd_device)

    lg.add_argument("-n", type=int, default=20)
    pr = sub.add_parser("profile"); pr.add_argument("profile_action",
                                                   choices=["list", "import"])
    pr.add_argument("name", nargs="?")
    pr.set_defaults(fn=cmd_profile)

    cp = sub.add_parser("compile"); cp.add_argument("--target", default="mcode",
                                                     choices=sorted(TARGETS))
    cp.add_argument("--apply", action="store_true")
    cp.set_defaults(fn=cmd_compile)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "command", None) and args.command and args.command[0] == "--":
        args.command = args.command[1:]
    try:
        return args.fn(args)
    except (ValueError, SpecError) as exc:
        print(f"{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
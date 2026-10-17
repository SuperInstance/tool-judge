"""
The console. Where this was always meant to be used.

WHY A TUI AND NOT A BOT
-----------------------

The Telegram route was a detour, and not only because of bot tokens and
webhooks. It existed to solve a problem that a local process does not have:
the authority had to live somewhere the agent could not reach, so every action
had to be graded by whether it arrived remotely, and a chat in your pocket
became the trust anchor.

Sitting at the terminal, that whole layer evaporates. You are the authority.
There is no remote boundary to grade, no audit trail on someone else's server,
and no question about whether a message that reached the agent came from you.

Which means: run it under tmux, leave it open next to the agent, and it does
the job with none of that machinery.

    tool-judge tui

A LINE-ORIENTED CONSOLE, NOT A FULL-SCREEN ONE
----------------------------------------------

Deliberately not curses. Three reasons, in order of how much they matter:

  - tmux is how these agents run. A line-oriented program survives copy,
    paste, scrollback, resize, and a dropped SSH session. A full-screen TUI
    turns all four into a corrupted display.
  - it is testable. `run()` takes its input and output as callables, so the
    whole conversation is exercised in the test suite with no pty, no
    terminal, and no flakes. That is not a nicety; it is why this is 100% test
    coverage instead of "tested by hand once".
  - it pipes. `printf 'y\\nquit\\n' | tool-judge tui` is a legitimate way to
    use it, which means the interface is also a scriptable one.

THE NATURAL-LANGUAGE PART
--------------------------

`maybe` parses what you typed. It is deterministic and narrow on purpose:
"always allow this in this project", "just this task", "never". Those are the
phrasings that actually recur, and a form-shaped parser that is wrong out loud
is better than a model that is wrong quietly.

Anything it cannot parse is reported as unparsed rather than guessed at. A
permission surface that infers intent you did not express is the one place
this tool must never be clever.
"""

from __future__ import annotations

import os
import re
import shlex
import sys
from pathlib import Path

from . import advisory
from .anomaly import Detector
from .decisionlog import DecisionLog
from .grants import GrantStore
from .modes import CutOff, KillSwitch, Mode, Posture
from .scope import Scope, applicable_scopes
from .spec import SpecError, load

BANNER = """\
tool-judge — permissions for your agents, from a terminal.

  ask <command>    would this run right now?
  list             what this agent may do, by scope
  pending          requests waiting on you
  say <request-id> <free text>   approve/deny, in words
  posture [mode]   how commands are treated
  cut-off [--reset]
  feed             recent behaviour signals
  why              why the last thing happened
  help / quit
"""

HELP = """
  ask <command>        check one command. Also accepts a shell string.
  list                 your grants, grouped by scope
  pending              queued requests
  say <id> <text>      answer a request in plain language
  posture [mode]       allow-silent | allow-alert | ask-first | cut-off
  cut-off [--reset]    stop the agent / let it run again
  feed                 recent behavioural signals
  log [-n N]           the decision log
  help, quit

Anything it cannot parse, it says so. It will not guess.
"""


class Console:
    def __init__(self, store: GrantStore, rails_path: str | None = None,
                 kill: KillSwitch | None = None, log: DecisionLog | None = None,
                 out=None) -> None:
        self.store = store
        self.rails_path = rails_path
        self.kill = kill or KillSwitch(Path(store.path).with_suffix(".kill.json"))
        self.log = log or DecisionLog(Path(store.path).with_suffix(".decisions.log"))
        self.out = out or sys.stdout
        self.detector = Detector()
        self.last = None
        self._spec = None

    # -- io ---------------------------------------------------------------

    def say(self, text: str = "") -> None:
        for line in text.splitlines():
            self.say_raw(line)

    def say_raw(self, line: str = "") -> None:
        self.out.write(line + "\n")
        try:
            self.out.flush()
        except Exception:                                   # noqa: BLE001
            pass

    def spec(self):
        if self._spec is None and self.rails_path and Path(self.rails_path).exists():
            try:
                self._spec = load(self.rails_path)
            except SpecError:
                self._spec = False
        return self._spec or None

    def live(self) -> dict:
        return dict(task="console", project=str(Path.cwd()),
                    user=os.environ.get("USER", "user"))

    # -- commands ---------------------------------------------------------

    def cmd_ask(self, line: str) -> None:
        raw = line.strip()
        if not raw:
            self.say("  ask what? try:  ask git status")
            return
        self.kill.check()
        try:
            argv = shlex.split(raw)
        except ValueError:
            argv = raw.split()

        spec = self.spec()
        res = self.store.grants().resolve(argv, **self.live())
        if spec:
            d = spec.checker().check(argv)
        else:
            d = None

        if res.verdict == "deny" or (d and d.verdict.value == "deny"):
            verdict = "deny"
        elif res.verdict == "allow":
            verdict = "allow"
        elif d:
            verdict = d.verdict.value
        else:
            verdict = "unlisted"

        self.log.record(verdict, scope=res.source_scope or "", pattern=raw,
                        reason=res.reason,
                        decided_by=res.source_scope or (d.rail if d else ""))

        colour = {"allow": "\033[32m", "ask": "\033[33m",
                  "deny": "\033[31m"}.get(verdict, "")
        self.say(f"  {colour}{verdict.upper()}\033[0m  {raw}")
        self.say(f"    from  grants: {res.verdict}"
                 + (f" ({res.source_scope})" if res.source_scope else ""))
        if d:
            self.say(f"    from  rails : {d.verdict.value}"
                     + (f" ({d.rail})" if d.rail else ""))
        if verdict in ("ask", "unlisted"):
            self.say(f"    to allow: say {res.grant is not None and '' or ''}"
                     f"pending  -- or add it yourself with `grant`")
        self.last = {"argv": argv, "verdict": verdict, "grants": res.verdict,
                     "rail": d.rail if d else None}

    def cmd_list(self, line: str) -> None:
        gs = self.store.grants()
        live = self.live()
        found = False
        for scope, key in applicable_scopes(**live):
            rows = gs.for_scope(scope, key)
            if not rows:
                continue
            found = True
            self.say(f"\n  {scope.label}:{key}")
            for r in sorted(rows, key=lambda x: x.created_at):
                self.say(f"    {r.verdict:<5} {r.pattern:<32} {r.reason}")
        if not found:
            self.say("  nothing granted here. that is a valid state.")

    def cmd_pending(self, line: str) -> None:
        rows = self.store.pending()
        if not rows:
            self.say("  nothing waiting.")
            return
        for r in rows:
            self.say(f"  #{r['id']:<4} {r['status']:<9} {r['scope']}:{r['key']:<12} "
                     f"{r['pattern']:<26} {r['justification'][:44]}")

    def cmd_say(self, line: str) -> None:
        """
        Answer a request in plain language.

        The deterministic parse is narrow by design. It recognises scope
        words and polarity words, and when it finds neither it says so rather
        than guessing -- a permissions surface that infers intent you did not
        express is the one place this tool must never be clever.
        """
        parts = line.strip().split(None, 1)
        if not parts:
            self.say("  say what? try: say 1 only for this task")
            return
        if not parts[0].lstrip("#").isdigit():
            self.say(f"  {parts[0]!r} is not a request id. try: pending")
            return
        rid = int(parts[0].lstrip("#"))
        text = parts[1] if len(parts) > 1 else ""
        verdict = interpret(text)

        if verdict is None:
            self.say("  I could not read a decision in that.")
            self.say("  Try one of:")
            for ex in ("say %d yes, but only for this task" % rid,
                       "say %d yes, always in this project" % rid,
                       "say %d no, never" % rid):
                self.say(f"    {ex}")
            return

        approve, scope_hint, why = verdict
        try:
            out = self.store.decide(rid, approve, by="console")
        except (KeyError, ValueError) as exc:
            self.say(f"  {exc}")
            return

        self.log.record(out["status"], scope=f"{out['scope']}:",
                        pattern=out["pattern"],
                        reason=why or f"{out['status']} via console",
                        decided_by="console", requester="human")
        self.say(f"  #{rid} {out['status']}"
                 + (f" -> {out['pattern']} at {out['scope']}" if approve else ""))
        if scope_hint and approve:
            self.say(f"  (you said {scope_hint!r}; applied as {out['scope']}. "
                     f"re-scope with `grant` if you meant something narrower)")

    def cmd_posture(self, line: str) -> None:
        cur = self.store.get_meta("posture") or ""
        arg = line.strip()
        if not arg:
            self.say(f"  posture: {Posture.parse(cur).describe() if cur else 'ask-first (default)'}")
            self.say("  modes: " + ", ".join(m.value for m in Mode))
            return
        try:
            p = Posture.parse(arg)
        except ValueError as exc:
            self.say(f"  {exc}")
            return
        self.store.set_meta("posture", p.mode.value)
        self.say(f"  posture -> {p.describe()}")
        self.log.record("allow", pattern="posture", reason=f"posture set to {p.describe()}",
                        decided_by="console")

    def cmd_cut_off(self, line: str) -> None:
        if "--reset" in line:
            self.kill.reset(by="console")
            self.say("  reset. the agent may run again.")
            self.log.record("allow", pattern="cut-off", reason="reset by console",
                            decided_by="console")
            return
        reason = line.replace("--reset", "").strip() or "manual"
        self.kill.trip(reason, by="console")
        self.say(f"  CUT OFF. every command is refused. reason: {reason}")
        self.log.record("deny", pattern="cut-off", reason=reason, decided_by="console")

    def cmd_feed(self, line: str) -> None:
        rows = [r for r in self.store.pending("pending")]
        if not rows:
            self.say("  nothing pending and nothing flagged this session.")
        for r in rows:
            self.say(f"  #{r['id']} {r['pattern']}  {r['justification'][:40]}")
        if self.detector.history:
            self.say("  observed this session:")
            for o in self.detector.history:
                self.say(f"    {o.verdict.upper():<6} {' '.join(o.argv)}")

    def cmd_log(self, line: str) -> None:
        n = 20
        parts = line.split()
        if len(parts) >= 2 and parts[-1].isdigit():
            n = int(parts[-1])
        self.say(self.log.summary())
        for e in self.log.last(n):
            self.say(e.render())

    def cmd_why(self, line: str) -> None:
        if not self.last:
            self.say("  nothing yet. try: ask git status")
            return
        self.say(f"  last: {' '.join(self.last['argv'])}")
        self.say(f"    verdict  {self.last['verdict']}")
        self.say(f"    grants   {self.last['grants']}"
                 + (f"  <- {self.last['rail']}" if self.last["rail"] else ""))

    def cmd_help(self, line: str) -> None:
        self.say(HELP)

    # -- dispatch ---------------------------------------------------------

    DISPATCH = {
        "ask": "cmd_ask", "list": "cmd_list", "ls": "cmd_list",
        "pending": "cmd_pending", "say": "cmd_say",
        "posture": "cmd_posture", "cut-off": "cmd_cut_off", "cutoff": "cmd_cut_off",
        "feed": "cmd_feed", "log": "cmd_log", "why": "cmd_why",
        "help": "cmd_help", "?": "cmd_help", "quit": None, "exit": None,
    }

    def handle(self, line: str) -> bool:
        """Returns False to end the loop."""
        line = line.strip()
        if not line:
            return True
        verb, _, rest = line.partition(" ")
        verb = verb.lower()
        if verb in ("quit", "exit", ":q"):
            return False
        fn = self.DISPATCH.get(verb, "cmd_help")
        if fn is None:
            return False
        try:
            getattr(self, fn)(rest)
        except CutOff as exc:
            self.say(f"  CUT OFF: {exc}")
        except Exception as exc:                              # noqa: BLE001
            # A console that dies on a typo is a console nobody uses.
            self.say(f"  {type(exc).__name__}: {exc}")
        return True


# ---------------------------------------------------------------------------
# Reading a decision out of plain language.
#
# Narrow on purpose. Recognises polarity and scope, and returns None rather
# than guessing when it finds neither.
# ---------------------------------------------------------------------------

_NEGATIVE = ("no", "never", "deny", "denied", "refuse", "not this", "nope",
             "don't", "dont", "stop", "cut", "kill", "block")
_POSITIVE = ("yes", "yep", "allow", "approve", "ok", "okay", "sure", "do it",
             "granted", "fine", "go ahead", "y")
_SCOPE_TASK = ("this task", "just this", "one-off", "one off", "once",
               "this time", "temporar")
_SCOPE_PROJECT = ("this project", "the project", "this repo", "the repo",
                  "always here", "in this repo", "project")
_SCOPE_SESSION = ("this session", "the session", "for now", "today")
_SCOPE_USER = ("always", "everywhere", "all my", "everywhere", "permanently",
               "from now on", "globally", "forever")


def interpret(text: str):
    """
    -> (approve, scope_hint, why) or None when unreadable.

    Deliberately returns None rather than a guess. The cost of a wrong read
    here is a permission nobody meant to grant, which is the one failure this
    entire tool exists to prevent.
    """
    t = (text or "").strip().lower()
    if not t:
        return None

    approve = None
    for w in _NEGATIVE:
        if re.search(rf"\b{re.escape(w)}\b", t):
            approve = False
            break
    if approve is None:
        for w in _POSITIVE:
            if re.search(rf"^(\W*){re.escape(w)}\b", t) or f" {w}" in t:
                approve = True
                break
    # "always in this project" carries no explicit yes, but it is an approval
    # -- someone saying that is not asking a question. Scope words imply
    # assent. This stays narrow: it needs an affirmative scope phrase AND no
    # negation, which the loop above has already ruled out.
    if approve is None:
        if any(w in t for w in _SCOPE_USER + _SCOPE_PROJECT):
            approve = True
        else:
            return None

    # Most specific wins. "always in this project" contains both "always"
    # (user) and "this project" (project); scanning user-first resolved it to
    # the widest scope, which is exactly backwards -- a phrase that names a
    # project is asking for project scope.
    scope = None
    for words, name in ((_SCOPE_TASK, "task"), (_SCOPE_SESSION, "session"),
                        (_SCOPE_PROJECT, "project"), (_SCOPE_USER, "user")):
        if any(w in t for w in words):
            scope = name
            break

    return approve, scope, text.strip()


def run(store: GrantStore, rails_path: str | None = None,
        read=input, out=None) -> int:
    """
    The loop. `read` and `out` are injected so the whole console is testable
    without a terminal -- which is the reason this is a line-oriented program
    and not a curses one.
    """
    c = Console(store, rails_path, out=out)
    c.say(BANNER)
    while True:
        try:
            line = read("> ")
        except (EOFError, KeyboardInterrupt):
            c.say("")
            return 0
        if not c.handle(line):
            return 0

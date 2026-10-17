"""
Response modes, and the one switch that must never fail.

WHAT THIS IS FOR
----------------

The user said, in effect: *I want to tell my permission agent how I want it to
behave, in words.* That decomposes into a small closed set of postures:

    allow-silent   permit, and say nothing
    allow-alert    permit, but tell me
    ask-first      queue it and wait for me
    cut-off        stop the agent and drop everything it holds

`allow-alert` is the interesting one and the reason this file exists: it is how
you get the benefit of autonomy without giving up the ability to notice when
the autonomy is wrong. You are not approving each command -- you are
subscribing to the ones you did not see.

THE KILL SWITCH
---------------

`cut-off` is not a posture, it is a guarantee, so it lives here rather than in
the posture table. It must:

    be local     it cannot depend on a network, a bot token, or a daemon that
                 might already be dead. If the remote channel is what told you
                 something was wrong, the remote channel is not where you
                 revoke.
    be durable   it survives a restart, or a crash is a way to lose the alarm
    be instant   no queue, no confirmation, no ordering
    be total     not "revoke the scopes I know about" -- everything the agent
                 holds, by walking the grants rather than trusting an index
    be logged    the one event nobody is watching is the one that matters

THE TRUST PROBLEM WITH REMOTE APPROVAL, STATED PLAINLY
-------------------------------------------------------

A remote chat that can grant permissions to a local shell is a weaker boundary
than a human at a keyboard, and it is worth being honest about why:

    - it works from a phone, so no physical presence is required
    - the audit trail lives in someone else's server, not on your machine
    - prompt injection becomes far worse: if agent context includes anything
      from the channel, an injected instruction can arrive as a "message"

So remote input is graded by how much it can do, and the grading is not
uniform:

    NOTIFY        safe from anywhere. Alerts, status, read-only queries.
    ACT ON PENDING narrow. Approve something already vetted locally, scoped
                   to one request id. Cannot invent new permissions.
    WIDEN         local only. New patterns, wider scopes. Never remote.
    CUT OFF       safe from anywhere, and should be the fastest thing you can
                   do.

The asymmetry is deliberate. Slowing down "give this agent more power" is the
entire point; slowing down "stop this agent" makes the system unusable exactly
when you need it.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Mode(str, Enum):
    ALLOW_SILENT = "allow-silent"
    ALLOW_ALERT = "allow-alert"
    ASK_FIRST = "ask-first"
    CUT_OFF = "cut-off"


@dataclass
class Posture:
    """How a command is treated, resolved through the scope chain.

    Defaults to ask-first, which is the same conservative default every other
    layer in this tool uses. An unstated posture is not permission.
    """
    mode: Mode = Mode.ASK_FIRST
    # Optional per-rail override, e.g. {"git-push": Mode.ALLOW_ALERT}
    overrides: dict[str, Mode] = field(default_factory=dict)

    def for_rail(self, rail: str | None) -> Mode:
        return self.overrides.get(rail, self.mode) if rail else self.mode

    @staticmethod
    def parse(text: str) -> "Posture":
        text = (text or "").strip()
        if not text:
            return Posture()
        if "=" in text and ":" not in text.split("=", 1)[0]:
            head, _, tail = text.partition("=")
            if head.strip() in {m.value for m in Mode}:
                ov = {}
                for part in tail.split(","):
                    rail, _, mode = part.partition(":")
                    if rail.strip() and mode.strip():
                        ov[rail.strip()] = Mode(mode.strip())
                return Posture(mode=Mode(head.strip()), overrides=ov)
        try:
            return Posture(mode=Mode(text))
        except ValueError:
            raise ValueError(
                f"unknown mode {text!r}; expected one of "
                f"{[m.value for m in Mode]} or 'mode=rail:mode,...'"
            ) from None

    def describe(self) -> str:
        base = self.mode.value
        if self.overrides:
            extra = ",".join(f"{k}={v.value}" for k, v in sorted(self.overrides.items()))
            return f"{base} ({extra})"
        return base


class KillSwitch:
    """
    The one component that must not fail.

    State is a small JSON file, written with fsync before the call returns, and
    read fresh on every check. It is deliberately not in the grants database:
    an agent with write access to the grants database should not be able to
    flip this, and the two living together would make that possible.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _write(self, state: dict) -> None:
        tmp = self.path.with_suffix(".tmp")
        with open(tmp, "w") as fh:
            json.dump(state, fh, indent=2)
            fh.flush()
            import os
            os.fsync(fh.fileno())
        tmp.replace(self.path)

    def trip(self, reason: str = "", by: str = "human") -> dict:
        state = {"tripped": True, "at": time.time(), "reason": reason, "by": by}
        self._write(state)
        return state

    def reset(self, by: str = "human") -> dict:
        state = {"tripped": False, "at": time.time(), "by": by,
                 "previous": self.state().get("reason", "")}
        self._write(state)
        return state

    def state(self) -> dict:
        if not self.path.exists():
            return {"tripped": False}
        try:
            return json.loads(self.path.read_text())
        except json.JSONDecodeError:
            # An unreadable switch file must READ AS TRIPPED. Failing open here
            # means a corrupt file silently disarms the alarm.
            return {"tripped": True, "reason": "state file unreadable"}

    def tripped(self) -> bool:
        return bool(self.state().get("tripped"))

    def check(self) -> None:
        """Raise if tripped. Call this on every command path."""
        if self.tripped():
            s = self.state()
            raise CutOff(
                f"agent cut off at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(s.get('at', 0)))}"
                f"{' — ' + s['reason'] if s.get('reason') else ''}"
                f"{' (by ' + s['by'] + ')' if s.get('by') else ''}"
            )


class CutOff(RuntimeError):
    """The agent has been stopped. Not retryable; not a transient error."""


def enforce(granted: str, posture: Posture, *, kill: KillSwitch | None = None,
            rail: str | None = None) -> tuple[str, dict]:
    """
    Resolve one already-decided command into an action plus context.

    Takes the VERDICT as a string rather than a grants object on purpose. An
    earlier signature duck-typed `grants.verdict`, and the caller was passing
    a GrantSet, which has no such attribute -- so every command silently
    looked "unlisted" and every posture degraded to `ask`. The bug was
    invisible because `ask` is a plausible answer; it took a test asserting
    that allow-silent actually returns `allow` to find it.

    `granted` is what scope.py already resolved: allow | ask | deny | unlisted.

    Returns (action, context) where action is one of:
        "allow" | "alert" | "ask" | "deny"

    `allow` and `alert` are the same decision -- the difference is whether the
    human hears about it -- and keeping them distinct is the whole
    convenience of the allow-alert posture: an autonomous agent can still be
    one you are watching.
    """
    if kill is not None:
        kill.check()

    mode = posture.for_rail(rail)
    if mode is Mode.CUT_OFF:
        raise CutOff(f"posture for rail {rail or '*'} is cut-off")

    if granted == "deny":
        return "deny", {"mode": mode.value, "granted": granted}
    if mode is Mode.ASK_FIRST:
        return "ask", {"mode": mode.value, "granted": granted}
    if granted == "unlisted":
        # Never auto-allow something nobody declared, whatever the posture.
        # allow-alert on an undeclared command is how autonomy becomes
        # unbounded while still looking supervised -- the alerts exist, so it
        # feels watched, while nothing was ever declared.
        return "ask", {"mode": mode.value, "granted": granted,
                       "note": "unlisted command; posture cannot widen it"}
    if granted == "ask":
        return "ask", {"mode": mode.value, "granted": granted}
    if mode is Mode.ALLOW_ALERT:
        return "alert", {"mode": mode.value, "granted": granted}
    return "allow", {"mode": mode.value, "granted": granted}


# ---------------------------------------------------------------------------
# Remote control, graded.
#
# The distinction that keeps a Telegram chat from becoming a weaker terminal.
# ---------------------------------------------------------------------------

#: What a remote channel may do. Anything not listed here is LOCAL ONLY.
REMOTE_CAPABILITIES = {
    "notify":      "send alerts, answer status queries, read logs",
    "act_pending": "approve or refuse a request id that already exists, "
                   "and only that request",
    "cut_off":     "trip the kill switch. No confirmation, no latency budget.",
}

#: Never remote, under any setting. Slowing these down is the point.
LOCAL_ONLY = {"widen", "grant_new", "reset_kill_switch", "edit_rails"}


def remote_check(action: str) -> tuple[bool, str]:
    """
    May `action` arrive over a remote channel?

    Separate function on purpose: the answer must be reachable from whatever
    transport is bolted on later -- a bot handler, an HTTP endpoint, a cron --
    without those layers re-deriving the policy and getting it subtly wrong.
    """
    if action in LOCAL_ONLY:
        return False, (f"{action!r} is local-only by design; "
                       f"a remote channel must not be able to widen an agent")
    cap = REMOTE_CAPABILITIES.get(action)
    if cap is None:
        return False, f"unknown remote action {action!r}"
    return True, cap
"""
Scoped grants: permissions that travel with the work instead of the machine.

THE PROBLEM WITH A FLAT ALLOWLIST
---------------------------------

The allowlist on this box had 214 entries, most of them `["tail","-3"]` --
one human click each. It has no idea what any of them were for. The same
command is safe in one project and meaningless in another, the same grant is
right in one session and wrong six months later, and a command that is
perfectly fine on the laptop can brick a Jetson.

So the unit of permission stops being "this command" and becomes "this
command, in this scope". Scopes nest:

    task       <- this piece of work, dies with it
    session    <- this working session
    project    <- this directory and its rails
    hardware   <- this physical machine (a specific Orin, a specific G1)
    developer  <- this person, across projects
    user       <- everything, everywhere

Narrowest wins. A grant made for one task does not follow you to another
project, and a hardware grant cannot fire on a different box -- which is the
property that makes "just grab the safe set for that Orin" a real thing
rather than a metaphor.

THE PRECEDENCE RULE, and why it is not simply "narrowest wins"
-------------------------------------------------------------

    DENY at ANY applicable scope wins. Then narrowest-to-widest for the rest.

This is deliberately NOT plain narrowest-wins. Plain narrowest-wins means a
project could allow something the developer denied globally, and "I opened a
folder and it lost my safety rails" is not an acceptable failure mode. So a
deny is a floor no scope can dig under, and only allow/ask are scoped.

The cost is honest and worth naming: you cannot locally re-enable something
denied for you. To un-deny you edit the wider scope. That is the intent.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Iterable, Sequence


class Scope(IntEnum):
    """
    Ordered narrowest to widest. The integer order IS the precedence order,
    so sorting is the resolution and there is no separate priority column to
    get out of sync with the semantics.
    """
    TASK = 0
    SESSION = 1
    PROJECT = 2
    HARDWARE = 3
    DEVELOPER = 4
    USER = 5

    @classmethod
    def parse(cls, name: str) -> "Scope":
        try:
            return cls[name.strip().upper()]
        except KeyError:
            raise ValueError(
                f"unknown scope {name!r}; expected one of "
                f"{[s.name.lower() for s in cls]}"
            ) from None

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Grant:
    """
    One permission, at one scope.

    `pattern` is the same `<program>:<arg-glob>` shape as a rail, so the same
    matcher serves both and there is no second dialect to learn.
    """
    scope: Scope
    key: str
    pattern: str
    verdict: str          # allow | ask | deny
    reason: str = ""
    granted_by: str = "human"
    created_at: float = 0.0

    def describe(self) -> str:
        scope = f"{self.scope.label}:{self.key}"
        return f"{self.verdict:<5} {scope:<28} {self.pattern}"


@dataclass(frozen=True)
class Resolution:
    verdict: str
    reason: str
    grant: Grant | None
    considered: int = 0

    @property
    def source_scope(self) -> str | None:
        return f"{self.grant.scope.label}:{self.grant.key}" if self.grant else None


def applicable_scopes(
    *,
    task: str | None = None,
    session: str | None = None,
    project: str | None = None,
    hardware: str | None = None,
    developer: str | None = None,
    user: str | None = None,
) -> list[tuple[Scope, str]]:
    """
    The scopes that apply right now, narrowest first.

    Absent scopes are simply not in the list. That is the whole mechanism
    behind "that grant does not travel": on a different machine `hardware` is
    a different key, so a hardware grant is not applicable and simply is not
    consulted.
    """
    out = [
        (Scope.TASK, task),
        (Scope.SESSION, session),
        (Scope.PROJECT, project),
        (Scope.HARDWARE, hardware),
        (Scope.DEVELOPER, developer),
        (Scope.USER, user),
    ]
    return [(s, k) for s, k in out if k]


class GrantSet:
    """
    A collection of grants, resolved against a set of live scopes.

    Holds no I/O. The SQLite store in `grants.py` loads rows into a GrantSet
    and forgets about them, which keeps resolution testable without a
    database -- which is the point, because the resolution rules are where
    the bugs live.
    """

    def __init__(self, grants: Iterable[Grant] = ()) -> None:
        self.grants = list(grants)

    def add(self, grant: Grant) -> "GrantSet":
        self.grants.append(grant)
        return self

    def extend(self, grants: Iterable[Grant]) -> "GrantSet":
        self.grants.extend(grants)
        return self

    # -- queries ---------------------------------------------------------

    def for_scope(self, scope: Scope, key: str) -> list[Grant]:
        return [g for g in self.grants if g.scope is scope and g.key == key]

    def applicable(self, **scopes) -> list[Grant]:
        live = dict(applicable_scopes(**scopes))
        return [g for g in self.grants
                if (g.scope, g.key) in live or g.scope is Scope.USER]

    # -- resolution ------------------------------------------------------

    def resolve(self, argv: Sequence[str], **scopes) -> Resolution:
        """
        Resolve one command. See the module docstring for precedence.

        Within a single scope, later grants win, because granting something
        again is how you change your mind and the newest statement should be
        the one that counts.
        """
        from .rails import Pattern

        live = applicable_scopes(**scopes)
        live_keys = dict(live)
        considered = 0

        # Pass 1: any applicable deny wins, at any depth. This is the floor.
        for scope, key in live:
            for g in self.grants:
                if g.scope is not scope or g.key != key:
                    continue
                if g.verdict != "deny":
                    continue
                if Pattern.compile(g.pattern).matches(argv):
                    considered += 1
                    return Resolution("deny", g.reason or f"denied by {g.describe()}",
                                      g, considered)

        # Pass 2: narrowest-first allow/ask.
        for scope, key in live:
            hits = [g for g in self.grants
                    if g.scope is scope and g.key == key
                    and g.verdict in ("allow", "ask")
                    and Pattern.compile(g.pattern).matches(argv)]
            if hits:
                g = hits[-1]          # newest wins within a scope
                considered += len(hits)
                return Resolution(g.verdict, g.reason or f"{g.describe()}",
                                  g, considered)

        return Resolution("unlisted", "no applicable grant covers this", None,
                          considered)

    # -- introspection ----------------------------------------------------

    def inventory(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for g in self.grants:
            k = f"{g.scope.label}:{g.key}"
            out[k] = out.get(k, 0) + 1
        return out

    def describe(self) -> str:
        if not self.grants:
            return "(no grants)"
        rows = sorted(self.grants,
                      key=lambda g: (g.scope, g.key, g.created_at))
        return "\n".join(g.describe() for g in rows)
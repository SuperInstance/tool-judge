"""
Declarative rails: the part that actually enforces.

`perm-rules` was a hardcoded allowlist for one machine on one project. The
thing worth generalising is not the list -- it is that the list should be
*derived from a written statement of what the project is*, so that changing
the project's safety posture is editing prose rather than editing Python.

That is what this module is: rails in, verdicts out, no model involved.

THE SPLIT THAT MAKES THE WHOLE THING HONEST
-------------------------------------------

    deterministic layer (this file)   enforces. No model, no network, no
                                      chance of being talked into anything.

    goal-fit layer (goalfit.py)       advises. A model, may be wrong, fails
                                      open, annotates rather than blocks.

Conflating them is how a "safety layer" becomes an unreliable one. An agent
that asks a language model whether it may run `rm -rf` has built a suggestion
box where it needed a wall. This file is the wall; `goalfit.py` is the label
on the door.

WHY THE PATTERN FORMAT IS `<program>:<arg-glob>`
-----------------------------------------------

Because that is the shape permission stores already use, so a rail can compile
straight to a host-native rule with no translation loss. See `compile.py`.
"""

from __future__ import annotations

import fnmatch
import shlex
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Sequence


class Verdict(str, Enum):
    """What the checker concluded. Ordered worst-first for reporting."""

    DENY = "deny"
    ASK = "ask"
    ALLOW = "allow"


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str
    rail: str | None = None
    annotated: str | None = None

    def __str__(self) -> str:
        bits = [self.verdict.value.upper()]
        if self.rail:
            bits.append(f"[{self.rail}]")
        bits.append(self.reason)
        if self.annotated:
            bits.append(f"note: {self.annotated}")
        return " ".join(bits)


def split_command(argv: Sequence[str]) -> str:
    """Rebuild a shell-ish command string. Used only for glob matching."""
    try:
        return " ".join(shlex.quote(a) for a in argv)
    except ValueError:
        return " ".join(argv)


@dataclass(frozen=True)
class Pattern:
    """
    One compiled rail pattern.

    Two forms, decided by whether the text before the first ":" looks like a
    program name:

      "git push:*"        program "git push", any arguments
      ".venv/bin/python*" whole-string glob, because the head has a "/" and
                          therefore is a path, not a bare program
    """
    raw: str
    program: str | None
    arg_glob: str

    @classmethod
    def compile(cls, raw: str) -> "Pattern":
        head, sep, tail = raw.partition(":")
        # A bare program name has no path separator, no glob, and no space.
        # "git push" is two words but is still a program path for our purposes.
        looks_like_program = (
            sep
            and "/" not in head
            and not any(c in head for c in "*?[")
        )
        if looks_like_program:
            return cls(raw, head, tail)
        return cls(raw, None, raw)

    def matches(self, argv: Sequence[str]) -> bool:
        if not argv:
            return False
        if self.program is None:
            return fnmatch.fnmatch(" ".join(argv), self.arg_glob)

        # The program may be several words -- "git push", not just "git".
        # Match a prefix of argv, not argv[0], or every subcommand rail is
        # silently dead. This was a real bug: the first version compared
        # argv[0] == "git push", which is never true, so 24 of 40-odd rails
        # matched nothing and every git command fell through to ASK.
        words = self.program.split(" ")
        if len(argv) < len(words):
            return False
        if " ".join(argv[:len(words)]) != self.program:
            return False
        return fnmatch.fnmatch(" ".join(argv[len(words):]), self.arg_glob)


@dataclass
class Rail:
    """One named constraint."""

    name: str
    kind: Verdict
    patterns: list[Pattern] = field(default_factory=list)
    why: str = ""
    # Set when the rail exists to stop something irreversible rather than to
    # stop something merely unwanted. Drives the wording of the refusal.
    irreversible: bool = False

    def hit(self, argv: Sequence[str]) -> bool:
        return any(p.matches(argv) for p in self.patterns)


class Checker:
    """
    Evaluates a command against a project's rails.

    Order matters and is the whole security property: deny is evaluated
    before ask, and ask before allow. A command that matches a deny rail is
    refused even if a broader allow rail would have covered it. This mirrors
    what the mcode permission engine does (deny at step 1a, before the allow
    path), so the compiled rules and this checker cannot disagree about which
    one wins.
    """

    def __init__(self, rails: Iterable[Rail] = ()) -> None:
        self.rails: list[Rail] = list(rails)

    # -- construction ---------------------------------------------------

    @classmethod
    def from_spec(cls, spec) -> "Checker":
        """Build from a loaded `spec.Spec`. Kept separate so tests can hand
        build a Checker without touching the file format."""
        return cls(spec.rails)

    # -- evaluation -----------------------------------------------------

    def check(self, argv: Sequence[str], *, cwd: str | None = None) -> Decision:
        if not argv:
            return Decision(Verdict.DENY, "empty command", rail="malformed")

        for verdict in (Verdict.DENY, Verdict.ASK):
            for rail in self.rails:
                if rail.kind is not verdict:
                    continue
                if rail.hit(argv):
                    return Decision(
                        rail.kind,
                        rail.why or rail.name,
                        rail=rail.name,
                    )

        for rail in self.rails:
            if rail.kind is Verdict.ALLOW and rail.hit(argv):
                return Decision(Verdict.ALLOW, rail.why or rail.name,
                                rail=rail.name)

        # Nothing matched a rail. Unlisted is ASK, not ALLOW.
        #
        # This is the choice that makes the tool honest rather than
        # convenient. An empty allowlist is not permission to do anything; it
        # is permission to do nothing that was declared safe. Anything else is
        # a decision the project has not made yet, and an agent that runs it
        # unasked has made that decision on the project's behalf.
        return Decision(
            Verdict.ASK,
            "matches no rail -- the project has not declared this command",
            rail=None,
        )

    def check_all(self, commands: Iterable[Sequence[str]],
                  **kw) -> list[Decision]:
        return [self.check(c, **kw) for c in commands]

    # -- introspection --------------------------------------------------

    def rail_names(self) -> list[str]:
        return [r.name for r in self.rails]

    def by_verdict(self, verdict: Verdict) -> list[Rail]:
        return [r for r in self.rails if r.kind is verdict]

    def refusals(self) -> list[Rail]:
        """Rails that block something irreversible. Worth showing the user."""
        return [r for r in self.rails if r.irreversible]
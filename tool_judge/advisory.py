"""
Should this request even be made?

A broker that accepts any well-formed request is a rubber stamp with extra
steps. This is the layer that says *this one looks wrong* before a human
spends attention on it.

THE THREE QUESTIONS
-------------------

1. Is the SCOPE too wide for the justification? An agent asking for `user`
   scope to run one command this task does not need a rubber stamp, it needs
   a question. Narrow scope is not bureaucratic; it is what makes the layer
   worth having.

2. Is the PATTERN one the project's own rails would refuse? Requesting `sudo:*`
   is not automatically wrong -- but it is never routine, and the person
   approving should know it collides with their own standing constraint
   before they say yes.

3. Is the JUSTIFICATION load-bearing, or is it a vibe? A justification that
   merely restates the command ("need to run kubectl") has not argued for
   anything.

NONE OF THIS BLOCKS. It annotates, and the human still decides. The moment
this starts refusing, it becomes a policy engine with opinions, and policy
engines with opinions get bypassed.
"""

from __future__ import annotations

from dataclasses import dataclass

from .scope import Scope

# Patterns whose scope should be earned, not granted on a first ask. These
# are broad enough that a narrow scope is almost always available instead.
WIDE_SCOPE_NEEDS_JUSTIFICATION = 40


@dataclass
class Flag:
    severity: str        # "info" | "warn" | "refuse-recommendation"
    title: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.severity}] {self.title}: {self.detail}"


#: Verbs that mean "this is the whole command", not "this is one command".
BROAD_MARKERS = ("*", ".*", "all")


def review(pattern: str, scope: str, justification: str,
           *, rails=None) -> list[Flag]:
    """
    Annotate a pending request. Returns flags; empty means nothing stood out.

    `rails`, when given, is a loaded Spec, so a request that collides with the
    project's own rails can be flagged against the actual rail rather than a
    guess.
    """
    flags: list[Flag] = []
    just = (justification or "").strip()

    # -- 1. scope wider than the justification ----------------------------
    if scope in (Scope.USER.label, Scope.DEVELOPER.label) and len(just) < WIDE_SCOPE_NEEDS_JUSTIFICATION:
        flags.append(Flag(
            "refuse-recommendation",
            "scope looks too wide for this justification",
            f"{scope} scope lasts forever and applies everywhere, but the "
            f"reason given is {len(just)} characters. A task or project scope "
            f"would cover this and could be withdrawn. Ask for that first."))

    if scope == Scope.HARDWARE.label and not just:
        flags.append(Flag(
            "warn", "device-scoped request with no reason",
            "hardware grants bind to one physical machine. If that is wrong, "
            "the command either will not run or will run somewhere it should "
            "not."))

    # -- 2. collision with the project's own rails -----------------------
    argv = _as_argv(pattern)
    if rails is not None and argv:
        d = rails.checker().check(argv)
        if d.verdict.value == "deny":
            flags.append(Flag(
                "warn", "collides with a rail that will still refuse it",
                f"even if approved, `{d.rail}` will deny this: "
                f"{d.reason[:110]}"))

    # -- 3. a justification that argues nothing --------------------------
    if not just:
        flags.append(Flag("info", "no justification given",
                          "a request without a reason is a request to be "
                          "trusted; approve or refuse on the command alone."))
    elif just.lower().startswith(("need to ", "run ", "use ", "execute ")):
        verb, _, rest = just.partition(" ")
        if pattern.split(":")[-1].rstrip("*") and rest.startswith(pattern.split(":")[0]):
            flags.append(Flag(
                "info", "justification restates the command",
                f"{just!r} says what the command is, not why it is needed. "
                f"What would go wrong without it?"))

    # -- 4. a pattern so broad it is a category, not a permission ---------
    tail = pattern.split(":", 1)[-1]
    if tail.strip() in BROAD_MARKERS:
        flags.append(Flag(
            "refuse-recommendation",
            "pattern matches everything",
            f"{pattern!r} permits the program unconditionally. Name the "
            f"operations that are actually needed instead."))

    return flags


def _as_argv(pattern: str) -> list[str]:
    """Best-effort argv from a `<program>:<args>` pattern, for rail checking."""
    if ":" in pattern:
        head, _, tail = pattern.partition(":")
        if "/" not in head and not any(c in head for c in "*?["):
            parts = head.split() + [tail.replace("*", "x").replace("?", "x")]
            return [p for p in parts if p]
    return []
"""
Load and validate a rails file.

The format is intentionally boring YAML. A safety rail that requires a
schema plugin is a safety rail that nobody writes.

A rails file has three blocks and they are not interchangeable:

    rails:     deterministic. Compiles to host-native rules. Enforces.
    context:   prose. Goes to the goal-fit judge. Advises.
    posture:   how the judge behaves when its model is unavailable.

The separation is the point. `context` holds the things a human would call
"the goals of this project" -- what the hardware is, what the budget is, what
would be embarrassing to break. None of it is enforceable, and the loader
refuses to pretend otherwise by never letting a `context` entry become a rail.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .rails import Checker, Pattern, Rail, Verdict


class SpecError(ValueError):
    """The rails file is malformed. Loudly -- a half-read safety rail is a
    safety rail that is not there."""


@dataclass
class Spec:
    name: str
    rails: list[Rail] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    posture: dict[str, Any] = field(default_factory=dict)
    source: Path | None = None

    def checker(self) -> Checker:
        return Checker(self.rails)

    def context_digest(self) -> str:
        """Flatten `context` into the prose digest the judge reads.

        Deliberately small models: winnow:e4b has a short context and the
        digest has to survive being read in one shot. Everything the judge can
        usefully know about the project should fit in a few hundred words; if
        it does not, the digest is not the place to put it.
        """
        out: list[str] = []
        for key, val in self.context.items():
            if isinstance(val, (list, tuple)):
                items = "\n".join(f"  - {v}" for v in val)
                out.append(f"{key}:\n{items}")
            else:
                out.append(f"{key}: {val}")
        return "\n".join(out)


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise SpecError(msg)


def load(path: str | Path) -> Spec:
    path = Path(path)
    _require(path.exists(), f"no rails file at {path}")
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise SpecError(f"{path}: not valid YAML: {exc}") from exc

    _require(isinstance(raw, dict), f"{path}: top level must be a mapping")

    name = str(raw.get("name") or path.stem)
    rails: list[Rail] = []

    seen: set[str] = set()
    for entry in raw.get("rails") or []:
        _require(isinstance(entry, dict), "each rail must be a mapping")
        rname = entry.get("name")
        _require(rname, "every rail needs a name: rails are how a refusal "
                        "explains itself, so an unnamed rail can only say no")
        _require(rname not in seen, f"duplicate rail name {rname!r}")
        seen.add(rname)

        kind_s = entry.get("kind")
        try:
            kind = Verdict(str(kind_s))
        except ValueError as exc:
            raise SpecError(
                f"rail {rname!r}: kind must be allow|ask|deny, got {kind_s!r}"
            ) from exc

        patterns = entry.get("patterns") or []
        _require(isinstance(patterns, list) and patterns,
                 f"rail {rname!r}: needs at least one pattern")

        why = str(entry.get("why") or "")
        if kind is Verdict.DENY:
            _require(why, f"rail {rname!r} denies something and must say why; "
                          f"an unexplained refusal is indistinguishable from a bug")

        rails.append(Rail(
            name=str(rname),
            kind=kind,
            patterns=[Pattern.compile(str(p)) for p in patterns],
            why=why,
            irreversible=bool(entry.get("irreversible", False)),
        ))

    context = raw.get("context") or {}
    _require(isinstance(context, dict),
             "context must be a mapping of project facts")

    posture = raw.get("posture") or {}
    _require(isinstance(posture, dict), "posture must be a mapping")

    return Spec(name=name, rails=rails, context=context, posture=posture,
                source=path)


def merge(base: Spec, overlay: Spec) -> Spec:
    """
    Layer rails files: later wins for the same rail NAME, appends otherwise.

    Name-keyed rather than index-keyed on purpose. A project that wants to
    relax one rail writes a two-line overlay naming it; it does not have to
    restate the other forty and it cannot accidentally drop them.
    """
    merged: dict[str, Rail] = {r.name: r for r in base.rails}
    for r in overlay.rails:
        merged[r.name] = r
    ctx = dict(base.context)
    ctx.update(overlay.context)
    post = dict(base.posture)
    post.update(overlay.posture)
    return Spec(name=overlay.name or base.name,
                rails=list(merged.values()),
                context=ctx, posture=post,
                source=overlay.source or base.source)
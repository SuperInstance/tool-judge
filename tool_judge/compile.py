"""
Compile rails into whatever the host actually enforces.

A rail file that only a Python process can read is a suggestion. This turns
the deterministic half into rules the permission store applies before the
model is ever consulted, so the refusal happens in the harness and not in
the agent's judgement.

Two targets today, because those are the two hosts this exists between:

    mcode     ~/.minimax/permission.json  {allow, deny, ask} of exact patterns
    claude    ~/.claude/settings.json     permissions.{allow,deny,ask}

Both are MERGE-ONLY. This module has no code path that removes an existing
rule, because a safety tool that can silently un-deny something is a tool
that will eventually un-deny something it should not have.

One thing it will not do: compile `context`. Context is prose for a judge.
There is no honest way to turn "the display is 120 characters" into a command
pattern, and a compiler that pretended otherwise would be inventing an
enforcement that does not exist.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from .rails import Rail, Verdict
from .spec import Spec


# -- targets ---------------------------------------------------------------

# One compiler, not two.
#
# An earlier version of this file carried its own TARGETS table. That was a
# second implementation of "where does this harness keep its permissions",
# and two implementations of one fact is how they drift -- the same class of
# bug this repo exists to catch. harness.py is now the only place that knows
# a permission file's shape, and it also carries the refusal rule: an adapter
# nobody has verified on this machine does not write.
from .harness import UnverifiedAdapter, get as _adapter, known as _known, \
    verified as _verified

TARGETS = {n: {"path": _adapter(n).path, "verified": _adapter(n).verified}
           for n in _known()}


def plan(spec: Spec, target: str = "mcode") -> dict[str, list]:
    """What WOULD change. Pure -- no filesystem writes."""
    return _adapter(target).plan(spec.rails)


def diff(spec: Spec, target: str = "mcode") -> str:
    p = plan(spec, target)
    total = sum(len(v) for v in p.values())
    if not total:
        return f"nothing to add; {TARGETS[target]['path']} is up to date"
    lines = [f"{len(p['allow'])} allow, {len(p['ask'])} ask, {len(p['deny'])} deny"]
    for verdict in ("deny", "ask", "allow"):
        if p[verdict]:
            lines.append(f"  [{verdict}]")
            for r in p[verdict][:200]:
                lines.append(f"    {r['matcher']['pattern'] if 'matcher' in r else r.get('pattern')}")
            if len(p[verdict]) > 200:
                lines.append(f"    ... and {len(p[verdict]) - 200} more")
    return "\n".join(lines)


def apply(spec: Spec, target: str = "mcode", *, backup: bool = True,
          force: bool = False) -> str:
    res = _adapter(target).apply(spec.rails, backup=backup, force=force)
    if not res.verified and res.problems:
        return res.summary() + "\n  " + "\n  ".join(res.problems)
    return res.summary()


def uninstall(spec: Spec, target: str = "mcode") -> str:
    """
    Remove exactly the rules this spec generated. Backs up first.

    This is the one place the tool removes rules, and it removes ONLY rules
    it can prove it wrote -- matched by exact pattern, never a prefix or a
    wildcard. A guard that could delete "rules that look like mine" would
    eventually delete yours.
    """
    tgt = TARGETS[target]
    path: Path = tgt["path"]
    doc = _read(path)
    mine = {p.raw for r in spec.rails for p in r.patterns}
    make = tgt["rule"]

    removed = 0
    for bucket in ("allow", "ask", "deny"):
        keep = []
        for r in doc.get(bucket, []):
            pat = (r.get("matcher", {}).get("pattern") if "matcher" in r
                   else r.get("pattern"))
            if pat in mine and r == make(pat):
                removed += 1
            else:
                keep.append(r)
        doc[bucket] = keep

    if not removed:
        return f"nothing of this spec's is present in {path}"

    bdir = path.parent / f"{path.stem}-backups"
    bdir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    shutil.copy2(path, bdir / f"{path.stem}-{stamp}{path.suffix}")
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2) + "\n")
    tmp.replace(path)
    return f"removed {removed} rule(s) from {path}"



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

MCODE_PERMISSION = Path.home() / ".minimax" / "permission.json"
CLAUDE_SETTINGS = Path.home() / ".claude" / "settings.json"

TARGETS = {
    "mcode": {
        "path": MCODE_PERMISSION,
        "list_key": {"Verdict.ALLOW": "allow", "Verdict.ASK": "ask",
                     "Verdict.DENY": "deny"},
        "rule": lambda p: {"tool_name": "bash",
                           "matcher": {"kind": "command", "pattern": p}},
    },
    "claude": {
        "path": CLAUDE_SETTINGS,
        "list_key": {"Verdict.ALLOW": "allow", "Verdict.ASK": "ask",
                     "Verdict.DENY": "deny"},
        "rule": lambda p: {"tool_name": "Bash", "pattern": p},
    },
}


def _read(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        # Do not overwrite a file we could not parse. A corrupt permission
        # store is a problem to report, not to paper over by rewriting it.
        raise SystemExit(
            f"refusing to write: {path} exists but is not valid JSON.\n"
            f"Move it aside and re-run; nothing has been changed."
        )


def plan(spec: Spec, target: str = "mcode") -> dict[str, list]:
    """What WOULD change. Pure -- no filesystem writes."""
    tgt = TARGETS[target]
    existing = _read(tgt["path"])
    key_for = tgt["list_key"]
    make = tgt["rule"]

    out: dict[str, list] = {"allow": [], "ask": [], "deny": []}
    have = {json.dumps(r, sort_keys=True)
            for lst in existing.values() if isinstance(lst, list)
            for r in lst}

    for rail in spec.rails:
        bucket = out[key_for[f"Verdict.{rail.kind.name}"]]
        for pat in rail.patterns:
            rule = make(pat.raw)
            k = json.dumps(rule, sort_keys=True)
            if k not in have:
                bucket.append(rule)
    return out


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


def apply(spec: Spec, target: str = "mcode", *, backup: bool = True) -> str:
    tgt = TARGETS[target]
    path: Path = tgt["path"]
    p = plan(spec, target)

    added = sum(len(v) for v in p.values())
    if not added:
        return f"nothing to add; {path} is up to date"

    doc = _read(path)
    doc.setdefault("version", 2)
    for bucket in ("allow", "ask", "deny"):
        doc.setdefault(bucket, [])
        have = {json.dumps(r, sort_keys=True) for r in doc[bucket]}
        for rule in p[bucket]:
            k = json.dumps(rule, sort_keys=True)
            if k not in have:
                have.add(k)
                doc[bucket].append(rule)

    if backup and path.exists():
        bdir = path.parent / f"{path.stem}-backups"
        bdir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        bak = bdir / f"{path.stem}-{stamp}{path.suffix}"
        shutil.copy2(path, bak)
        print(f"backup -> {bak}")

    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2) + "\n")
    tmp.replace(path)
    return (f"added {len(p['allow'])} allow, {len(p['ask'])} ask, "
            f"{len(p['deny'])} deny -> {path}")


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


def rails_of(spec: Spec, verdict: Verdict) -> list[Rail]:
    return [r for r in spec.rails if r.kind is verdict]
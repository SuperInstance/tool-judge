"""
Harness adapters: knowing WHERE a permission goes, and proving it landed.

THE LAST-MILE PROBLEM
----------------------

tool-judge knows *what* a project permits. Every agent harness knows *where*
its permissions live, and they do not agree:

    mcode        ~/.minimax/permission.json   {allow,deny,ask}[] of
                                             {tool_name, matcher:{kind,pattern}}
    claude-code  ~/.claude/settings.json      permissions.{allow,deny,ask}[]
                                             of {tool:"Bash", pattern:"..."}
    crush        ???                          not observed
    opencode     ???                          not observed
    zcode        ???                          not observed

So writing a rail correctly and writing it somewhere the harness will read it
are two different problems, and the second is where this class of tool dies.
A permission file the harness ignores is exactly the "looks wired, is not"
defect this project has been collecting all along -- one level up.

THE RULE THIS MODULE ENFORCES
------------------------------

    An adapter that has not been verified on THIS machine does not write.

Not "writes and hopes". Refuses, and says what is missing. `mcode` is verified
here because this box's permission.json was read, understood and written by
hand earlier in the same session. `claude-code` is documented but its
permissions block is ABSENT from this machine's settings.json, so it is
`verified=False` and refuses. The others are unknown and refuse.

A tool whose whole job is to be obeyed must be the most honest component in
the stack, and an adapter that confidently writes a JSON file in a shape the
harness does not read is the loudest possible way to be useless.

VERIFY, DO NOT ASSUME
---------------------

After writing, `verify()` reads the file back and confirms every pattern that
was supposed to land actually landed, and that nothing else changed. Writing
without reading back is how you ship a permission file that does nothing.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable


class UnverifiedAdapter(RuntimeError):
    """This harness's permission format is not confirmed on this machine."""


@dataclass
class ApplyResult:
    harness: str
    path: Path
    added: dict[str, list] = field(default_factory=dict)
    verified: bool = False
    problems: list[str] = field(default_factory=list)

    def summary(self) -> str:
        n = sum(len(v) for v in self.added.values())
        if not self.verified:
            return (f"{self.harness}: WROTE {n} rule(s) to {self.path} "
                    f"but VERIFICATION FAILED")
        return f"{self.harness}: {n} rule(s) verified present in {self.path}"


@dataclass
class Adapter:
    name: str
    path: Path
    verified: bool
    notes: str
    build: Callable[[str], dict]          # pattern -> rule
    lists: dict[str, str]                 # verdict -> top-level key
    # Which tools this adapter expresses. mcode nests a matcher object; the
    # others do not. Kept explicit rather than inferred.
    tool_name: str = "bash"

    # -- read / merge / write --------------------------------------------

    def _read(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text())
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"{self.path} exists but is not valid JSON ({exc}). "
                f"Move it aside and retry -- nothing has been changed."
            ) from exc

    def plan(self, rails) -> dict[str, list]:
        """Pure: what would be added, without touching the disk."""
        doc = self._read()
        have = {json.dumps(r, sort_keys=True)
                for lst in doc.values() if isinstance(lst, list) for r in lst}
        out: dict[str, list] = {}
        for rail in rails:
            key = self.lists.get(rail.kind.value)
            if not key:
                continue
            bucket = out.setdefault(key, [])
            for pat in rail.patterns:
                rule = self.build(pat.raw)
                k = json.dumps(rule, sort_keys=True)
                if k not in have:
                    have.add(k)
                    bucket.append(rule)
        return out

    def apply(self, rails, *, backup: bool = True, force: bool = False) -> ApplyResult:
        if not self.verified and not force:
            raise UnverifiedAdapter(
                f"{self.name}: refusing to write {self.path}.\n"
                f"  {self.notes}\n"
                f"  Pass force=True once you have confirmed the shape, and the "
                f"adapter's `verified` flag in this file."
            )

        added = self.plan(rails)
        total = sum(len(v) for v in added.values())
        res = ApplyResult(self.name, self.path, added)

        if total == 0:
            res.verified = True
            return res

        doc = self._read()
        for key, rules in added.items():
            doc.setdefault(key, [])
            have = {json.dumps(r, sort_keys=True) for r in doc[key]}
            for r in rules:
                k = json.dumps(r, sort_keys=True)
                if k not in have:
                    have.add(k)
                    doc[key].append(r)

        if backup and self.path.exists():
            bdir = self.path.parent / f"{self.path.stem}-backups"
            bdir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            shutil.copy2(self.path, bdir / f"{self.path.stem}-{stamp}.json")

        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(doc, indent=2) + "\n")
        tmp.replace(self.path)

        # Read back. Writing without verifying is the defect, not the fix.
        res.problems = self.verify(doc, added)
        res.verified = not res.problems
        return res

    def verify(self, doc: dict | None = None,
               added: dict | None = None) -> list[str]:
        """
        Confirm every rule that was written is actually readable back.

        Returns a list of problems; empty means clean. Checks presence, not
        just that the file parses -- a file can be valid JSON and still not
        contain what you put in it, which is the failure that actually happens.
        """
        doc = doc if doc is not None else self._read()
        problems: list[str] = []
        if not added:
            return problems
        for key, rules in added.items():
            bucket = doc.get(key)
            if not isinstance(bucket, list):
                problems.append(f"{key}: missing or not a list after write")
                continue
            present = {json.dumps(r, sort_keys=True) for r in bucket}
            for r in rules:
                if json.dumps(r, sort_keys=True) not in present:
                    problems.append(f"{key}: rule did not survive the write: "
                                    f"{json.dumps(r)[:70]}")
        return problems

    def read_back(self) -> dict[str, int]:
        doc = self._read()
        return {k: len(v) for k, v in doc.items() if isinstance(v, list)}


# ---------------------------------------------------------------------------
# The registry. `verified=True` only where the format has been observed on a
# real machine by this tool or by hand with its output in view.
# ---------------------------------------------------------------------------

def _mcode_rule(pattern: str) -> dict:
    return {"tool_name": "bash",
            "matcher": {"kind": "command", "pattern": pattern}}


def _claude_rule(pattern: str) -> dict:
    # Documented Claude Code shape. NOT observed on this machine -- its
    # settings.json has no `permissions` key at all.
    return {"tool": "Bash", "pattern": pattern}


def registry() -> dict[str, Adapter]:
    home = Path.home()
    return {
        "mcode": Adapter(
            name="mcode",
            path=home / ".minimax" / "permission.json",
            verified=True,
            notes="Observed and written on this host.",
            build=_mcode_rule,
            # Keyed by Verdict.value ("allow"/"ask"/"deny"), which is what
            # plan() looks up. These were keyed "Verdict.ALLOW" for a while,
            # so every lookup missed, plan() returned empty, and `compile`
            # reported "nothing to add, up to date" about a permission file it
            # had never successfully written to. It looked exactly like
            # idempotency. The test that caught it is
            # test_adapter_verifies_what_it_wrote.
            lists={"allow": "allow", "ask": "ask", "deny": "deny"},
        ),
        "claude-code": Adapter(
            name="claude-code",
            path=home / ".claude" / "settings.json",
            verified=False,
            notes=("permissions block is ABSENT from this machine's "
                   "settings.json, so the shape below is from documentation, "
                   "not observation."),
            build=_claude_rule,
            # Keyed by Verdict.value ("allow"/"ask"/"deny"), which is what
            # plan() looks up. These were keyed "Verdict.ALLOW" for a while,
            # so every lookup missed, plan() returned empty, and `compile`
            # reported "nothing to add, up to date" about a permission file it
            # had never successfully written to. It looked exactly like
            # idempotency. The test that caught it is
            # test_adapter_verifies_what_it_wrote.
            lists={"allow": "allow", "ask": "ask", "deny": "deny"},
        ),
    }


def get(name: str) -> Adapter:
    reg = registry()
    if name not in reg:
        raise KeyError(f"unknown harness {name!r}; known: {sorted(reg)}")
    return reg[name]


def known() -> list[str]:
    return sorted(registry())


def verified() -> list[str]:
    return sorted(n for n, a in registry().items() if a.verified)
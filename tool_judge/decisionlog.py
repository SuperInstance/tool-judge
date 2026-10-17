"""
Decision log: a reason a human can read six months from now.

WHY A LOG AND NOT A COUNTER
---------------------------

Every layer in this tool produces a number or a flag. A float is honest but
opaque: `score=0.5712` does not tell anyone *why*, and cannot be argued with
or learned from. A boolean is worse. When something goes wrong -- and it will
-- the question is always "what was it thinking?", and a number cannot answer
it.

So every decision appends a sentence. Not telemetry. A record someone can read
and disagree with, which is the only kind of log that changes behaviour.

    2026-10-17 09:14:22  ALLOW  task:t7  kubectl:*  -- the agent asked to
      inspect the staging cluster; scope kept at task so it cannot outlive
      the work that justified it

    2026-10-17 09:15:03  DENY   user:casey  sudo:*  -- never grant root; this
      is the developer's standing constraint, not a per-command judgement

The second entry is worth more than both a grant table and an audit log, and
it is the one a schema cannot produce: it says WHY, in the words of whoever
made the call.

FORMAT. Plain JSONL, one object per line. Not a database table, because the
first thing anyone does with a log is `grep` it, and `sqlite3` is a worse
`grep` than `grep`.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

VERDICTS = ("allow", "ask", "deny", "unlisted", "degraded")


@dataclass
class Entry:
    ts: float
    verdict: str
    scope: str
    pattern: str
    reason: str
    decided_by: str = ""
    requester: str = ""

    def render(self) -> str:
        head = (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts))
                + f"  {self.verdict.upper():<9} {self.scope:<18} {self.pattern}")
        who = f"  [{self.decided_by}]" if self.decided_by else ""
        return f"{head}{who}\n      {self.reason}"

    def to_json(self) -> str:
        return json.dumps(asdict(self))


class DecisionLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, verdict: str, *, scope: str = "", pattern: str = "",
               reason: str = "", decided_by: str = "",
               requester: str = "") -> Entry:
        if verdict not in VERDICTS:
            raise ValueError(f"verdict must be one of {VERDICTS}, got {verdict!r}")
        e = Entry(ts=time.time(), verdict=verdict, scope=scope,
                  pattern=pattern, reason=reason, decided_by=decided_by,
                  requester=requester)
        with self.path.open("a") as fh:
            fh.write(e.to_json() + "\n")
        return e

    def entries(self) -> list[Entry]:
        if not self.path.exists():
            return []
        out: list[Entry] = []
        for line in self.path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            out.append(Entry(**d))
        return out

    def last(self, n: int = 20) -> list[Entry]:
        return self.entries()[-n:]

    def summary(self) -> str:
        """Counts by verdict. The sentence version of the histogram."""
        es = self.entries()
        if not es:
            return "(no decisions recorded yet)"
        by: dict[str, int] = {}
        for e in es:
            by[e.verdict] = by.get(e.verdict, 0) + 1
        parts = [f"{v} {n}" for v, n in sorted(by.items())]
        return f"{len(es)} decisions: " + ", ".join(parts)


# ---------------------------------------------------------------------------
# The phrases worth keeping.
#
# A generic reason string ("permitted") is worth nothing. These are the
# sentences that turn a row into a record, and they exist as constants so
# every layer says the same thing about the same situation.
# ---------------------------------------------------------------------------

REASONS = {
    "allow_by_grant":
        "permitted by an existing grant at this scope",
    "deny_by_grant":
        "refused by an existing grant; a deny at any scope outranks an allow",
    "allow_by_rail":
        "permitted by the project's rails",
    "deny_by_rail":
        "refused by the project's rails, which are a floor no grant overrides",
    "ask_unlisted":
        "nobody has declared this command; an unlisted command is a question, "
        "not a permission",
    "ask_rail":
        "the rails require a human for this",
    "degraded":
        "the goal-fit judge was unreachable, so no opinion was recorded; the "
        "gate failed open, which is its documented posture",
    "narrow_scope_note":
        "scope was kept as narrow as the justification allows",
}
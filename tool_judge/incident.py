"""
Turning an alert into a conversation instead of a siren.

AN ALERT IS NOT AN ANSWER
-------------------------

`anomaly.py` can say "rm was refused once and has now run with different
flags". That is a fact. It is not a conclusion, and the gap between them is
where this tool could do real damage if it papered over it.

So an incident never says "this agent is compromised". It says: here is what
happened, here is the most likely innocent explanation, here is the question
that would settle it. The human decides. That restraint is not politeness --
a guard that cries wolf is dismissed, and a dismissed guard is worse than no
guard because it teaches the human this whole class of signal is noise.

THE THREE QUESTIONS
-------------------

An incident opens with exactly three, because the person reading it has
attention for about three. Everything else is on demand.

    1. What happened      the evidence, in order, verbatim
    2. Is this expected   the most likely benign cause, named
    3. What would you like to do

And then it STOPS. It does not pick an action and execute it. An incident
handler that resolves itself is an incident handler that guesses on your
behalf at the exact moment you were least equipped to notice.

THE OPTIONS ARE NARROW ON PURPOSE
---------------------------------

Four, and not "ignore and continue":

    deny     refuse the command, keep working (the usual answer)
    investigate  stop, and look at where the instruction came from
    allow    permit, and remember why
    session  refuse, and refuse the whole class for this session

`investigate` is the one that matters. Almost every real incident traces back
to text the agent READ -- a README, an issue, a web page, a file the task
told it to read. Once you know that, the fix is to sanitise the input rather
than to keep tightening permissions, and those are completely different
responses to the same symptom.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .anomaly import Alert, Severity

OPTIONS = ("deny", "investigate", "allow", "session")

OPTION_MEANING = {
    "deny": "Refuse this command; the agent carries on with something else.",
    "investigate": (
        "Stop here. Find out where the instruction came from -- almost always "
        "text the agent read rather than text it was given. Sanitising the "
        "input is the fix; tightening permissions only hides the symptom."
    ),
    "allow": "Permit it, and record that you did.",
    "session": (
        "Refuse this command and the whole class of it until the session ends, "
        "so you are not re-deciding the same thing every thirty seconds."
    ),
}


class Outcome(str, Enum):
    ALLOWED = "allow"
    DENIED = "deny"
    SESSION_DENIED = "session"
    INVESTIGATING = "investigate"


@dataclass
class Incident:
    alerts: list[Alert]
    agent: str = "agent"
    notes: list[str] = field(default_factory=list)

    @property
    def severity(self) -> Severity:
        order = [Severity.INFO, Severity.WARN, Severity.HIGH]
        return max((a.severity for a in self.alerts),
                   key=order.index, default=Severity.INFO)

    def headline(self) -> str:
        n = len(self.alerts)
        # Severity is a str Enum, so there is no .values() to rank with.
        # Ordering is stated here, once.
        rank = {"info": 0, "warn": 1, "high": 2}
        worst = max((rank[a.severity.value] for a in self.alerts), default=0)
        return (f"{self.severity.value.upper()}: {n} signal"
                f"{'s' if n > 1 else ''} from {self.agent}"
                f"{f' (worst signal {self.severity.value})' if n > 1 and worst else ''}")

    def opening(self) -> str:
        """
        What a person reads first. Three questions, then silence.

        Deliberately NOT a wall of text: the evidence is short by construction
        because the detector only keeps a small window.
        """
        lines = ["", "=" * 68, self.headline(), "=" * 68, ""]

        lines.append("1. WHAT HAPPENED")
        for a in self.alerts:
            lines.append(f"   [{a.kind}] {a.title}")
            for e in a.evidence:
                lines.append(f"      {e}")
        lines.append("")

        lines.append("2. IS THIS EXPECTED?")
        seen: set[str] = set()
        for a in self.alerts:
            for b in a.benign_explanations:
                if b not in seen:
                    seen.add(b)
                    lines.append(f"   - {b}")
        if not seen:
            lines.append("   - (no benign explanation offered -- treat as odd)")
        lines.append("")

        lines.append("3. WHAT WOULD YOU LIKE TO DO")
        for opt in OPTIONS:
            lines.append(f"   [{opt:<12}] {OPTION_MEANING[opt]}")
        lines.append("")
        lines.append("   It will wait. It will not guess, and it will not act twice.")
        lines.append("=" * 68)
        return "\n".join(lines)

    def apply(self, choice: str) -> Outcome:
        """Record the human's decision. The only writer of consequences."""
        c = (choice or "").strip().lower()
        if c not in OPTIONS:
            raise ValueError(f"choice must be one of {OPTIONS}, got {choice!r}")
        if c == "deny":
            return Outcome.DENIED
        if c == "investigate":
            self.notes.append("human chose to investigate the input source")
            return Outcome.INVESTIGATING
        if c == "session":
            return Outcome.SESSION_DENIED
        return Outcome.ALLOWED


def investigate_prompts(agent_recent_texts: list[str] | None = None) -> list[str]:
    """
    The questions worth asking when `investigate` is chosen.

    Ordered so that the cheapest, most likely answer comes first. Most
    incidents resolve at question one, and an investigation that opens with
    the hard question gets answered shallowly.
    """
    return [
        "Which file, page or issue did the agent read just before this?",
        "Did that text contain instructions -- to you, or to the agent?",
        "Was this task one where reading outside-authored text was expected?",
        "Would you be surprised to see this command in any task at all?",
        "Do you want the session's remaining grants reviewed before continuing?",
    ]
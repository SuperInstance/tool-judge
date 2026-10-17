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
handler that resolves itself is one that guesses on your behalf at the exact
moment you were least equipped to notice.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tool_judge.anomaly import Detector, Observation   # noqa: E402
from tool_judge.incident import (Incident, Outcome, OPTIONS,  # noqa: E402
                                 investigate_prompts)


def obs(argv, verdict="allow"):
    return Observation(ts=0.0, argv=tuple(argv), verdict=verdict)


def test_incident_opens_with_three_questions():
    d = Detector()
    d.observe(obs(["rm", "-rf", "scratchdir"], "deny"))
    a = d.observe(obs(["rm", "-f", "scratchdir"], "allow"))
    text = Incident(a, agent="tmux/glasses").opening()
    assert "1. WHAT HAPPENED" in text
    assert "2. IS THIS EXPECTED?" in text
    assert "3. WHAT WOULD YOU LIKE TO DO" in text


def test_incident_never_accuses():
    """
    It must not claim the agent was compromised. It reports a pattern and
    offers an innocent cause; the conclusion belongs to the human.

    Every word checked here is an accusation. A guard that asserts
    "compromised" from a pattern match is lying, and the person who catches
    it will stop reading the tool's output entirely.
    """
    d = Detector()
    d.observe(obs(["sudo", "rm", "-rf", "data"], "deny"))
    a = d.observe(obs(["doas", "rm", "-r", "data"], "allow"))
    text = Incident(a).opening().lower()
    for word in ("compromised", "malicious", "injected", "attacker", "breach",
                 "hacked", "attack"):
        assert word not in text, f"incident accused the agent: {word!r}"


def test_incident_offers_the_investigation_path():
    d = Detector()
    d.observe(obs(["rm", "-rf", "scratchdir"], "deny"))
    a = d.observe(obs(["rm", "-f", "scratchdir"], "allow"))
    text = Incident(a).opening()
    assert "investigate" in text
    assert "text the agent read" in text


def test_incident_lists_every_option():
    inc = Incident([])
    text = inc.opening()
    for opt in OPTIONS:
        assert f"[{opt}" in text


def test_incident_does_not_resolve_itself():
    d = Detector()
    d.observe(obs(["rm", "-rf", "scratchdir"], "deny"))
    a = d.observe(obs(["rm", "-f", "scratchdir"], "allow"))
    inc = Incident(a)
    assert inc.apply("deny") is Outcome.DENIED
    assert inc.apply("investigate") is Outcome.INVESTIGATING
    assert inc.apply("allow") is Outcome.ALLOWED
    assert inc.apply("session") is Outcome.SESSION_DENIED


def test_investigation_is_recorded():
    d = Detector()
    d.observe(obs(["sudo", "apt", "install", "x"], "deny"))
    a = d.observe(obs(["doas", "apt", "install", "x"], "allow"))
    inc = Incident(a)
    inc.apply("investigate")
    assert any("investigate" in n for n in inc.notes)


def test_incident_rejects_a_non_choice():
    inc = Incident([])
    try:
        inc.apply("probably fine")
    except ValueError:
        pass
    else:
        raise AssertionError("a free-text action would defeat the point")


def test_severity_is_the_worst_of_the_alerts():
    from tool_judge.anomaly import Severity
    d = Detector()
    d.observe(obs(["rm", "-f", "a"], "allow"))
    d.observe(obs(["rm", "-r", "b"], "allow"))
    a = d.observe(obs(["rm", "-rf", "c"], "allow"))
    assert Incident(a).severity is Severity.WARN


def test_investigation_asks_where_the_text_came_from_first():
    q = investigate_prompts()
    assert "read" in q[0].lower(), "cheapest, most likely answer should lead"
    assert len(q) >= 4
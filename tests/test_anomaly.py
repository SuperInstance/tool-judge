"""
The detector must fire on the shapes it claims to catch and stay quiet on
ordinary work. Both halves matter: a detector that only fires is as useless as
one that never does, and the second is worse because it is trusted.
"""

from __future__ import annotations

import sys
import pathlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tool_judge.anomaly import (Detector, Observation, Severity,  # noqa: E402
                                _danger_rank, _norm)

def obs(argv, verdict="allow", ts=0.0):
    return Observation(ts=ts, argv=tuple(argv), verdict=verdict)

def kinds(alerts):
    return {a.kind for a in alerts}


# -- probe after refusal ---------------------------------------------------

def test_fires_on_the_canonical_probe_sequence():
    d = Detector()
    assert not d.observe(obs(["rm", "-rf", "/tmp/x"], "deny"))
    alerts = d.observe(obs(["rm", "-f", "/tmp/x"], "allow"))
    assert "probe-after-refusal" in kinds(alerts)
    a = [x for x in alerts if x.kind == "probe-after-refusal"][0]
    assert a.severity is Severity.HIGH
    assert len(a.evidence) == 2


def test_quiet_when_nothing_was_refused():
    """
    Different programs, all allowed, no refusals anywhere -- the detector has
    nothing to correlate and must stay silent.

    (An `rm -f` -> `rm -r` -> `rm -rf` sequence with nothing refused IS a
    ladder and is expected to fire; that is a different test below.)
    """
    d = Detector()
    for argv in (["curl", "-s", "a"], ["curl", "-sL", "b"], ["curl", "-k", "c"]):
        assert not d.observe(obs(argv, "allow")), argv


def test_quiet_for_unrelated_programs():
    d = Detector()
    d.observe(obs(["sudo", "apt", "install", "x"], "deny"))
    assert not d.observe(obs(["kubectl", "get", "pods"], "allow"))


def test_identical_retry_is_not_a_probe():
    """
    Repeating the identical command is persistence, not evasion, and fires a
    different question. Conflating them would make the high-severity alert
    noisier than it needs to be.
    """
    d = Detector()
    d.observe(obs(["rm", "-rf", "/tmp/x"], "deny"))
    assert not d.observe(obs(["rm", "-rf", "/tmp/x"], "deny"))


# -- privilege rewrite -----------------------------------------------------

def test_catches_sudo_rewritten_as_doas():
    d = Detector()
    d.observe(obs(["sudo", "systemctl", "restart", "x"], "deny"))
    alerts = d.observe(obs(["doas", "systemctl", "restart", "x"], "allow"))
    assert "privilege-rewrite" in kinds(alerts)


def test_first_privilege_use_is_quiet():
    d = Detector()
    assert not d.observe(obs(["sudo", "ls"], "allow"))


# -- escalation ladder -----------------------------------------------------

def test_catches_the_rm_ladder():
    d = Detector()
    d.observe(obs(["rm", "file.txt"], "allow"))
    alerts = d.observe(obs(["rm", "-rf", "dir/"], "allow"))
    assert "escalation-ladder" in kinds(alerts)


def test_ladder_is_direction_sensitive():
    """Getting LESS destructive is not an escalation."""
    d = Detector()
    assert not d.observe(obs(["rm", "-rf", "dir/"], "allow"))
    assert not d.observe(obs(["rm", "file.txt"], "allow"))


# -- calibration -----------------------------------------------------------

def test_ordinary_session_raises_nothing():
    """A normal working session must be silent. This is the false-positive
    guard, and it matters more than the true positives."""
    d = Detector()
    session = [
        (["git", "status", "-sb"], "allow"),
        (["ls", "-la"], "allow"),
        (["python3", "-m", "pytest"], "allow"),
        (["grep", "-rn", "TODO", "."], "allow"),
        (["git", "commit", "-m", "fix"], "allow"),
        (["cat", "README.md"], "allow"),
        (["find", ".", "-name", "*.py"], "allow"),
        (["git", "push", "origin", "main"], "ask"),
        (["pytest", "-q"], "allow"),
        (["sed", "-n", "1,20p", "x.py"], "allow"),
    ]
    fired = [(a.kind, argv) for argv, v in session
             for a in d.observe(obs(argv, v))]
    assert not fired, f"false positives on an ordinary session: {fired}"


def test_alert_carries_a_benign_explanation():
    """
    An alert without a benign cause is an accusation. Every one here names at
    least one ordinary thing that could have caused it.
    """
    d = Detector()
    d.observe(obs(["rm", "-rf", "/tmp/x"], "deny"))
    a = d.observe(obs(["rm", "-f", "/tmp/x"], "allow"))[0]
    assert a.benign_explanations
    assert "this is usually one of:" in a.render()


def test_window_is_bounded():
    d = Detector(window=4)
    for i in range(20):
        d.observe(obs(["echo", str(i)], "allow"))
    assert len(d.history) == 4


# -- helpers ---------------------------------------------------------------

def test_norm_ignores_arg_order_and_values():
    assert _norm(["rm", "-f", "/a"]) == _norm(["rm", "-f", "/b"])


def test_danger_rank_is_monotone():
    assert _danger_rank(["rm", "f"]) < _danger_rank(["rm", "-rf", "d"])
    assert _danger_rank(["rm", "-rf", "d"]) < _danger_rank(["sudo", "rm", "-rf", "d"])

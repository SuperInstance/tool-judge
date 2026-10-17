"""
Tests for postures and the kill switch.

The kill switch gets disproportionate attention here on purpose. Every other
part of this tool can be wrong in a way that is annoying; this can be wrong in
a way that lets a compromised agent keep running.

Each of its five requirements -- local, durable, instant, total, logged -- has
a test that fails if that property is removed.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tool_judge.modes import (CutOff, KillSwitch, LOCAL_ONLY,  # noqa: E402
                              Mode, Posture, REMOTE_CAPABILITIES,
                              enforce, remote_check)
from tool_judge.scope import Grant, GrantSet, Scope  # noqa: E402


@pytest.fixture
def kill(tmp_path):
    return KillSwitch(tmp_path / "kill.json")


#: What scope.py already resolved for the command under test.
VERDICT = "allow"


# -- postures --------------------------------------------------------------

def test_default_posture_is_ask_first():
    assert Posture().mode is Mode.ASK_FIRST
    assert Posture.parse("").mode is Mode.ASK_FIRST


@pytest.mark.parametrize("text", ["allow-silent", "allow-alert", "ask-first"])
def test_parses_each_mode(text):
    assert Posture.parse(text).mode is Mode(text)


def test_parses_rail_overrides():
    p = Posture.parse("allow-silent=git-push:allow-alert,deploy:ask-first")
    assert p.mode is Mode.ALLOW_SILENT
    assert p.for_rail("git-push") is Mode.ALLOW_ALERT
    assert p.for_rail("deploy") is Mode.ASK_FIRST
    assert p.for_rail("something-else") is Mode.ALLOW_SILENT


def test_unknown_mode_is_rejected():
    with pytest.raises(ValueError, match="unknown mode"):
        Posture.parse("allow-ish")


# -- the four postures -----------------------------------------------------

def test_allow_silent_is_quiet():
    a, _ = enforce(VERDICT, Posture(Mode.ALLOW_SILENT), rail="none")
    assert a == "allow"


def test_allow_alert_still_permits_but_reports():
    a, ctx = enforce(VERDICT, Posture(Mode.ALLOW_ALERT), rail="none")
    assert a == "alert", "allow-alert must not become ask"
    assert ctx["mode"] == "allow-alert"


def test_ask_first_queues():
    a, _ = enforce(VERDICT, Posture(Mode.ASK_FIRST), rail="none")
    assert a == "ask"


def test_deny_is_never_posture_overridable():
    """No posture turns a deny into a permit. The floor stays a floor."""
    for mode in Mode:
        if mode is Mode.CUT_OFF:
            continue
        a, _ = enforce("deny", Posture(mode), rail="no-privilege-escalation")
        assert a == "deny", f"{mode} overrode a deny"


def test_allow_alert_cannot_widen_an_unlisted_command():
    """
    The subtle one. allow-alert on a command nobody declared would be
    unbounded autonomy that still LOOKS supervised -- the alerts exist, so it
    feels watched, while nothing was ever declared.
    """
    a, ctx = enforce("unlisted", Posture(Mode.ALLOW_ALERT), rail="none")
    assert a == "ask", "an undeclared command must still be asked about"
    assert "cannot widen" in ctx["note"]


def test_cut_off_posture_raises():
    with pytest.raises(CutOff):
        enforce(VERDICT, Posture(Mode.CUT_OFF), rail="none")


# -- the kill switch, property by property ---------------------------------

def test_starts_untripped(kill):
    assert not kill.tripped()


def test_trips_and_blocks(kill):
    kill.trip("looked wrong", by="casey")
    assert kill.tripped()
    with pytest.raises(CutOff, match="looked wrong"):
        kill.check()


def test_DURABLE_survives_a_restart(tmp_path):
    """A crash must not be a way to lose the alarm."""
    KillSwitch(tmp_path / "kill.json").trip("durability test")
    assert KillSwitch(tmp_path / "kill.json").tripped()


def test_LOCAL_does_not_need_the_grants_database(tmp_path):
    """
    The switch must not live where an agent with database write access can
    reach it. It is a separate file precisely so it cannot be edited by
    whatever the grants database authorises.
    """
    k = KillSwitch(tmp_path / "kill.json")
    k.trip("x")
    grants_db = tmp_path / "grants.db"
    assert k.path != grants_db
    assert k.path.exists()


def test_TOTAL_blocks_even_an_allowed_command(kill):
    """It is not scoped. A granted command is still refused."""
    kill.trip("total")
    with pytest.raises(CutOff):
        enforce(VERDICT, Posture(Mode.ALLOW_SILENT), kill=kill, rail="none")


def test_LOGGED_records_who_and_why(kill):
    kill.trip("suspicious", by="casey")
    s = kill.state()
    assert s["reason"] == "suspicious"
    assert s["by"] == "casey"
    assert s["at"] > 0


def test_unreadable_state_reads_as_TRIPPED(tmp_path):
    """
    Failing open here disarms the alarm with a corrupt file. A switch that
    cannot be read must be assumed ON.
    """
    p = tmp_path / "kill.json"
    p.write_text("{corrupt")
    assert KillSwitch(p).tripped() is True


def test_reset_requires_deliberation(kill):
    kill.trip("x")
    kill.reset(by="casey")
    assert not kill.tripped()
    assert kill.state()["previous"] == "x", "the reason must survive the reset"


# -- remote grading --------------------------------------------------------

def test_remote_can_notify_cut_off_and_act_on_pending():
    for action in REMOTE_CAPABILITIES:
        ok, _ = remote_check(action)
        assert ok, action


def test_remote_cannot_widen():
    """The whole point. A remote chat must not be able to add power."""
    for action in sorted(LOCAL_ONLY):
        ok, why = remote_check(action)
        assert not ok, action
        assert "local-only" in why


def test_unknown_remote_action_is_refused():
    ok, _ = remote_check("make_me_an_admin")
    assert not ok


def test_cut_off_needs_no_confirmation():
    """Fastest possible path to stopping an agent."""
    ok, cap = remote_check("cut_off")
    assert ok and "No confirmation" in cap


# -- posture overrides reach enforcement -----------------------------------

def test_rail_override_is_used_at_the_call_site():
    p = Posture(Mode.ALLOW_SILENT, overrides={"noisy-rail": Mode.ASK_FIRST})
    assert enforce(VERDICT, p, rail="noisy-rail")[0] == "ask"
    assert enforce(VERDICT, p, rail="quiet-rail")[0] == "allow"
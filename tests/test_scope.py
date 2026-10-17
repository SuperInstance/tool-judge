"""
Scoped grants: does the precedence rule actually hold?

These tests are about one property -- a narrow allow cannot dig under a wide
deny -- and about the property that makes the whole idea worth building: a
grant made for one context does not follow you into another.

If these are right, `python3` approved for a Jetson is inert on the laptop, and
no project folder can quietly re-enable something the developer denied.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tool_judge.grants import GrantStore          # noqa: E402
from tool_judge.scope import Grant, GrantSet, Scope, applicable_scopes  # noqa: E402


def g(scope, key, pattern, verdict="allow", reason=""):
    return Grant(Scope.parse(scope) if isinstance(scope, str) else scope,
                 key, pattern, verdict, reason)


@pytest.fixture
def gs():
    return GrantSet([
        g("user", "casey", "rm -rf:*", "deny", "never delete anything"),
        g("project", "/work/glasses", "rm -rf:*", "allow", "scratch dir"),
        g("project", "/work/glasses", "python3:*"),
        g("session", "s1", "git commit:*"),
        g("task", "t1", "curl:*"),
        g("hardware", "orion-01", "jetson_clocks:*"),
        g("hardware", "orion-01", "sudo:*", "deny", "no root on a device"),
    ])


LIVE = dict(task="t1", session="s1", project="/work/glasses",
            hardware="orion-01", developer="casey", user="casey")


# -- the floor --------------------------------------------------------------

def test_deny_at_wide_scope_beats_allow_at_narrow(gs):
    """The load-bearing test. Opening a project folder must not un-deny rm."""
    r = gs.resolve(["rm", "-rf", "build"], **LIVE)
    assert r.verdict == "deny", r
    assert r.grant.scope is Scope.USER, "the deny should name its own scope"


def test_deny_at_narrow_scope_also_wins(gs):
    r = gs.resolve(["sudo", "jetson_clocks"], **LIVE)
    assert r.verdict == "deny", r
    assert r.source_scope == "hardware:orion-01"


# -- scope isolation --------------------------------------------------------

def test_narrowest_allow_wins_when_nothing_denies(gs):
    r = gs.resolve(["curl", "-s", "https://example.com"], **LIVE)
    assert r.verdict == "allow"
    assert r.source_scope == "task:t1"


def test_grant_does_not_travel_to_another_task(gs):
    """The property that makes scoping worth having."""
    r = gs.resolve(["curl", "-s", "x"], **{**LIVE, "task": "t2"})
    assert r.verdict != "allow", "a task grant leaked into another task"
    assert r.source_scope is None


def test_grant_does_not_travel_to_another_machine(gs):
    """
    The hardware case, and the reason hardware scope exists: a grant earned on
    one physical unit must be inert on another.
    """
    r = gs.resolve(["jetson_clocks", "--show"], **{**LIVE, "hardware": "orin-02"})
    assert r.verdict != "allow", "a hardware grant fired on a different device"


def test_grant_does_not_travel_to_another_project(gs):
    r = gs.resolve(["python3", "x.py"], **{**LIVE, "project": "/work/other"})
    assert r.verdict != "allow"


def test_user_scope_is_the_floor_that_always_applies(gs):
    """A user grant with no other scope present still applies."""
    r = gs.resolve(["rm", "-rf", "x"], task=None, session=None, project=None,
                   hardware=None, developer=None, user="casey")
    assert r.verdict == "deny"


# -- unlisted ---------------------------------------------------------------

def test_unlisted_is_not_allow(gs):
    r = gs.resolve(["kubectl", "delete", "ns", "prod"], **LIVE)
    assert r.verdict == "unlisted"
    assert r.grant is None


def test_empty_argv(gs):
    assert gs.resolve([], **LIVE).verdict == "unlisted"


# -- ordering ---------------------------------------------------------------

def test_scopes_are_ordered_narrow_to_wide():
    assert (Scope.TASK < Scope.SESSION < Scope.PROJECT
            < Scope.HARDWARE < Scope.DEVELOPER < Scope.USER)
    assert [s.label for s in sorted(Scope)] == \
        ["task", "session", "project", "hardware", "developer", "user"]


def test_absent_scopes_are_not_consulted():
    live = applicable_scopes(task="t1", user="casey")
    assert live == [(Scope.TASK, "t1"), (Scope.USER, "casey")]


def test_newest_grant_wins_within_a_scope():
    s = GrantSet([
        g("user", "casey", "ls:*", "allow"),
        g("user", "casey", "ls:*", "deny", "changed my mind"),
    ])
    assert s.resolve(["ls", "-la"], user="casey").verdict == "deny"


def test_scope_parse_rejects_nonsense():
    with pytest.raises(ValueError, match="unknown scope"):
        Scope.parse("galaxy")


# -- persistence ------------------------------------------------------------

def test_store_roundtrip_and_profile_import():
    with tempfile.TemporaryDirectory() as tmp:
        s = GrantStore(Path(tmp) / "g.db")
        s.grant("hardware", "orin-01", "jetson_clocks:*", "allow")
        s.grant("hardware", "orin-01", "flash:*", "deny", reason="bricks the unit")
        s.save_profile("orin-safe", "hardware", "orin-01",
                       "Safe set for a shared Orin")

        assert s.grants().resolve(["jetson_clocks", "--show"],
                                  hardware="orin-01").verdict == "allow"
        assert s.grants().resolve(["flash", "x"], hardware="orin-01").verdict == "deny"

        n = s.import_profile("orin-safe")
        assert n == 2
        assert len(s.grants_from("profile-import").grants) == 2
        s.close()


def test_revoke_removes_exactly_one():
    with tempfile.TemporaryDirectory() as tmp:
        s = GrantStore(Path(tmp) / "g.db")
        s.grant("task", "t1", "curl:*", "allow")
        s.grant("task", "t1", "wget:*", "allow")
        assert s.revoke("task", "t1", "curl:*") == 1
        assert s.grants().resolve(["curl", "x"], task="t1").verdict == "unlisted"
        assert s.grants().resolve(["wget", "x"], task="t1").verdict == "allow"
        s.close()


def test_device_facts_persist():
    with tempfile.TemporaryDirectory() as tmp:
        s = GrantStore(Path(tmp) / "g.db")
        s.register_device("orin-01", "jetson-orin", label="bench unit",
                          facts={"spare_jtag": False, "writable_root": True})
        d = s.device("orin-01")
        assert d.fact("spare_jtag") is False
        assert d.fact("nonexistent", "default") == "default"
        s.close()


def test_unknown_machine_is_not_guessed():
    """Guessing a device id would let one box's grants apply to another."""
    with tempfile.TemporaryDirectory() as tmp:
        s = GrantStore(Path(tmp) / "g.db")
        s.register_device("orin-01", "jetson-orin")
        assert s.device("this") is None
        s.close()


def test_bad_verdict_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        s = GrantStore(Path(tmp) / "g.db")
        with pytest.raises(ValueError, match="allow\\|ask\\|deny"):
            s.grant("user", "casey", "ls:*", "probably")
        s.close()
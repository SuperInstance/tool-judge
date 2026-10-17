"""
The console, driven end to end with no terminal.

`run()` takes `read` and `out` as callables, which is the entire reason this
is a line-oriented program rather than a curses one: the whole conversation is
exercisable here, and it will be exercised every time the suite runs instead of
once by hand on a Tuesday.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tool_judge.grants import GrantStore       # noqa: E402
from tool_judge.scope import Scope             # noqa: E402
from tool_judge.tui import Console, interpret, run  # noqa: E402

RAILS = str(ROOT / "rails" / "g1-ble-backend.yaml")


@pytest.fixture
def console(tmp_path):
    store = GrantStore(tmp_path / "s.db")
    yield Console(store, RAILS, out=io.StringIO())
    store.close()


def feed(console, *lines):
    for ln in lines:
        assert console.handle(ln) is not False, f"loop ended early at {ln!r}"


def said(console):
    return console.out.getvalue()


# -- the interpreter -------------------------------------------------------

@pytest.mark.parametrize("text,approve,scope", [
    ("yes", True, None),
    ("yes but only for this task", True, "task"),
    ("always in this project", True, "project"),
    ("yep do it today", True, "session"),
    ("never", False, None),
    ("no, never do that", False, None),
    ("deny", False, None),
    ("approve", True, None),
])
def test_reads_common_phrasings(text, approve, scope):
    got = interpret(text)
    assert got is not None, text
    assert got[0] is approve
    assert got[1] == scope


@pytest.mark.parametrize("text", ["maybe later", "blah blah", "", "   "])
def test_refuses_to_guess(text):
    """A wrong read here grants a permission nobody meant to grant."""
    assert interpret(text) is None


def test_specific_scope_beats_broad_one():
    """'always in this project' is project scope, not user scope."""
    assert interpret("always in this project")[1] == "project"
    assert interpret("always")[1] == "user"


def test_negation_beats_implicit_approval():
    assert interpret("never do this in this project")[0] is False


# -- commands --------------------------------------------------------------

def test_ask_reports_both_layers(console):
    feed(console, "ask git status")
    out = said(console)
    assert "ALLOW" in out
    assert "from  rails" in out, "the deciding layer must be named"


def test_ask_a_denied_command(console):
    feed(console, "ask sudo rm /etc/hosts")
    assert "DENY" in said(console)


def test_list_with_nothing_granted_is_a_valid_state(console):
    feed(console, "list")
    assert "nothing granted" in said(console)


def test_list_after_granting(console):
    console.store.grant(Scope.TASK, "console", "pytest:*", "allow")
    feed(console, "list")
    assert "pytest:*" in said(console)


def test_posture_roundtrip(console):
    feed(console, "posture allow-alert")
    assert "allow-alert" in said(console)
    console.out.truncate(0), console.out.seek(0)
    feed(console, "posture")
    assert "allow-alert" in said(console)


def test_posture_rejects_nonsense(console):
    feed(console, "posture allow-ish")
    assert "unknown mode" in said(console)


def test_cut_off_blocks_ask_and_why(console):
    feed(console, "cut-off something looked wrong")
    assert "CUT OFF" in said(console)
    console.out.truncate(0), console.out.seek(0)
    feed(console, "ask git status")            # rails would say ALLOW
    assert "CUT OFF" in said(console)


def test_reset_lifts_it(console):
    feed(console, "cut-off x", "cut-off --reset")
    console.out.truncate(0), console.out.seek(0)
    feed(console, "ask git status")
    assert "ALLOW" in said(console)


# -- the request conversation ---------------------------------------------

def test_say_approves_and_the_grant_becomes_real(console):
    rid = console.store.request("project", "/x", "kubectl:*", "allow",
                                justification="inspect staging")
    feed(console, f"say {rid} yes but only for this task")
    assert console.store.grants().resolve(
        ["kubectl", "get", "pods"], project="/x").verdict == "allow"


def test_say_refuses_and_grants_nothing(console):
    rid = console.store.request("user", "casey", "rm:*", "allow",
                                justification="cleanup")
    feed(console, f"say {rid} never")
    assert console.store.grants().resolve(
        ["rm", "-rf", "x"], user="casey").verdict != "allow"


def test_say_with_unreadable_text_offers_examples(console):
    rid = console.store.request("task", "t", "ls:*", "allow",
                                justification="x")
    feed(console, f"say {rid} hmm maybe")
    out = said(console)
    assert "could not read" in out
    assert f"say {rid} yes" in out, "it should show what it CAN read"
    # and nothing was decided
    assert console.store.pending("pending")


def test_say_rejects_a_non_request_id(console):
    feed(console, "say banana yes")
    assert "not a request id" in said(console)


# -- robustness ------------------------------------------------------------

def test_a_typo_does_not_kill_the_console(console):
    """
    A console that dies on a typo is a console nobody uses. Feed it junk,
    then prove it still works afterwards.
    """
    feed(console, "flurb", "ask ls")
    assert "ALLOW" in said(console)


def test_empty_line_is_a_noop(console):
    feed(console, "", "   ", "ask ls")
    assert "ALLOW" in said(console)


def test_why_reports_the_last_decision(console):
    feed(console, "ask git status", "why")
    out = said(console)
    assert "last: git status" in out
    assert "verdict" in out


def test_log_records_what_happened(console):
    feed(console, "ask git status")
    assert "decisions" in console.log.summary()


# -- the loop --------------------------------------------------------------

def test_run_exits_on_quit(tmp_path):
    store = GrantStore(tmp_path / "s.db")
    out = io.StringIO()
    lines = iter(["ask git status", "quit"])
    rc = run(store, RAILS, read=lambda _p: next(lines), out=out)
    assert rc == 0
    assert "tool-judge" in out.getvalue()
    store.close()


def test_run_exits_on_eof(tmp_path):
    store = GrantStore(tmp_path / "s.db")
    def eof(_p):
        raise EOFError
    assert run(store, RAILS, read=eof, out=io.StringIO()) == 0
    store.close()


def test_console_is_pipeable(tmp_path):
    """`printf 'ask ls\\nquit\\n' | tool-judge tui` is a legitimate use."""
    import subprocess
    src = str(ROOT / "tool_judge" / "cli.py")
    r = subprocess.run(
        [sys.executable, "-m", "tool_judge.cli",
         "--store", str(tmp_path / "s.db"), "tui"],
        input="ask ls\nquit\n", capture_output=True, text=True, timeout=60,
        cwd=str(ROOT))
    assert r.returncode == 0, r.stderr[-400:]
    assert "tool-judge" in r.stdout
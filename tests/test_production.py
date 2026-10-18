"""
Production tests for the two halves that take real input from outside.

Config and Telegram both fail in ways that only show up under a real
deployment -- a missing secret, a chat that is not on the allowlist, a token
that leaks into an error message. None of that is reachable from the CLI
tests, so it gets its own file.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tool_judge.config import ConfigError, describe, load   # noqa: E402
from tool_judge.grants import GrantStore                     # noqa: E402
from tool_judge.modes import LOCAL_ONLY, KillSwitch          # noqa: E402
from tool_judge.telegram import Bot, Telegram                # noqa: E402


# -- config ----------------------------------------------------------------

def test_missing_token_is_not_a_default():
    c = load(env={})
    assert c.telegram_token is None
    assert not c.telegram_enabled


def test_env_overrides_file(tmp_path):
    f = tmp_path / "cfg.env"
    f.write_text("TELEGRAM_TOKEN=from_file\nTOOL_JUDGE_TIMEOUT=11\n")
    c = load(env={"TELEGRAM_TOKEN": "from_env"}, file=f)
    assert c.telegram_token == "from_env", "the environment must win"
    assert c.request_timeout == 11.0


def test_quoted_values_are_unwrapped(tmp_path):
    f = tmp_path / "c.env"
    f.write_text('TELEGRAM_TOKEN="abc"\nDECISION_URL=\'http://x:1\'\n')
    c = load(env={}, file=f)
    assert c.telegram_token == "abc"
    assert c.decision_url == "http://x:1"


def test_comments_and_blank_lines_are_skipped(tmp_path):
    f = tmp_path / "c.env"
    f.write_text("# a comment\n\nTELEGRAM_TOKEN=x\nnot_a_pair\n")
    assert load(env={}, file=f).telegram_token == "x"


def test_warns_when_a_bot_has_no_binding(tmp_path):
    """A bot anyone can bind is a bot anyone can use to cut you off."""
    c = load(env={"TELEGRAM_TOKEN": "abc"})
    problems = c.validate()
    assert any("claim it" in p for p in problems), problems


def test_ok_when_either_binding_is_present():
    ok_secret = load(env={"TELEGRAM_TOKEN": "a", "TELEGRAM_BIND_SECRET": "b"})
    assert ok_secret.validate() == []
    ok_list = load(env={"TELEGRAM_TOKEN": "a", "TELEGRAM_ALLOWED_CHATS": "42"})
    assert ok_list.validate() == []


def test_allowlist_without_token_is_a_problem():
    c = load(env={"TELEGRAM_ALLOWED_CHATS": "42"})
    assert any("nothing to apply to" in p for p in c.validate())


def test_bad_url_is_caught():
    assert load(env={"DECISION_URL": "127.0.0.1:11435"}).validate()


def test_require_ok_raises():
    with pytest.raises(ConfigError):
        load(env={"TELEGRAM_TOKEN": "a"}).require_ok()


def test_describe_never_prints_the_token():
    c = load(env={"TELEGRAM_TOKEN": "SECRET-TOKEN-VALUE",
                  "TELEGRAM_BIND_SECRET": "SECRET-BIND-VALUE"})
    out = describe(c)
    assert "SECRET-TOKEN-VALUE" not in out
    assert "SECRET-BIND-VALUE" not in out
    assert "set" in out


def test_json_config_is_accepted(tmp_path):
    f = tmp_path / "c.json"
    f.write_text(json.dumps({"TELEGRAM_TOKEN": "abc"}))
    assert load(env={}, file=f).telegram_token == "abc"


def test_chat_ids_parse():
    c = load(env={"TELEGRAM_TOKEN": "a", "TELEGRAM_ALLOWED_CHATS": "1, 2 3 x"})
    assert c.telegram_allowed_chats == (1, 2, 3), "junk must be skipped, not crash"


# -- the bot ---------------------------------------------------------------

class Clock:
    """A virtual clock, because the real one makes rate-limit tests flaky.

    `handle()` takes `now`, so a test can say exactly when a message arrives
    instead of racing wall time. Two tests in this file failed before this
    existed, in opposite directions: one relied on messages arriving slowly
    enough to pass the limiter, the other on them arriving fast enough to be
    throttled.

    Used by the handful of tests that actually care about timing -- the rest
    run with the limiter effectively disabled, so they cannot race.
    """
    def __init__(self, start=None, step=0.1):
        # A thousand seconds past the real clock, so a virtual timestamp is
        # unambiguously later than anything the fixture already recorded
        # against time.time(). Starting at a round 1000.0 put every message
        # *before* the fixture's own bind and the limiter silently ate it.
        #
        # `step` is small on purpose: the rate-limit tests need consecutive
        # messages to fall INSIDE the window (rate_limit=0.5 -> 2 seconds), so
        # a clock that leaps 2 seconds per call would never be throttled at
        # all. To escape the window, jump explicitly with `now.t + 10`.
        self.t = time.time() + 1000.0 if start is None else start
        self.step = step
    def __call__(self):
        self.t += self.step
        return self.t


def make_bot(tmp_path, name="b", **kw):
    """
    A bot with the rate limiter DISABLED (rate_limit=inf -> a zero-width
    window). The fixture below used to pass 1000, which is 1000 messages per
    second -- a one millisecond window -- so two consecutive calls inside a
    single test got silently throttled and the test failed for a reason that
    had nothing to do with what it was testing.
    """
    store = GrantStore(tmp_path / f"{name}.db")
    return Bot(store=store, kill=KillSwitch(tmp_path / f"{name}-kill.json"),
               bind_secret="s3cret", rate_limit=float("inf"), **kw)


@pytest.fixture
def bot(tmp_path):
    """Bound and ready: chat 1 is authenticated, limiter off."""
    b = make_bot(tmp_path)
    assert b.handle(1, "s3cret") is not None, "fixture starts bound"
    yield b
    b.store.close()


def test_wrong_secret_is_silent(tmp_path):
    b = make_bot(tmp_path, "unbound")
    assert b.handle(999, "guess") is None, "a wrong secret must get nothing"
    assert b.handle(999, "status") is None
    assert not b.bound_chats, "a failed bind must not register the chat"
    b.store.close()


def test_correct_secret_binds_and_answers(tmp_path):
    """A fresh bot, first contact: the secret binds, then commands work."""
    b = make_bot(tmp_path, "fresh")
    assert b.handle(999, "s3cret") is not None
    assert 999 in b.bound_chats
    assert b.handle(999, "status") is not None
    b.store.close()


def test_allowlist_is_absolute_and_sufficient(tmp_path):
    """
    A listed chat needs no secret -- the list IS the credential, which is what
    config.validate() promises when it accepts an allowlist without a secret.
    An unlisted chat is silent even when it knows the secret.
    """
    store = GrantStore(tmp_path / "b.db")
    b = Bot(store=store, kill=KillSwitch(tmp_path / "k.json"),
            bind_secret="s3cret", allowed_chats=(111,), rate_limit=0.001)
    assert b.handle(222, "s3cret") is None, "unlisted chat with the secret"
    assert b.handle(111, "status") is not None
    store.close()


def test_comparison_is_constant_time():
    """
    The bind check must not be `==`. Asserted structurally rather than by
    timing, because a timing test on a fast machine proves nothing; the point
    is that the right function is called.
    """
    import inspect
    import tool_judge.telegram as tg
    src = inspect.getsource(tg.Bot.authorised)
    assert "hmac.compare_digest" in src
    assert "supplied ==" not in src


def test_cut_off_works_and_reset_does_not(bot):
    assert "stopped" in bot.handle(1, "cut off looks wrong").text
    assert bot.kill.tripped()
    r = bot.handle(1, "reset")
    assert "local-only" in r.text.lower()
    assert bot.kill.tripped(), \
        "a refused reset must leave it cut off -- the previous version of this \
         test asserted the opposite, which is what a reset that HAD run would \
         have looked like"


def test_cut_off_survives_the_rate_limiter(bot):
    """
    Throttling must never swallow the one command whose job is to stop things.

    Set the limiter low, spend the budget on chatter, then cut off. If the
    limiter were applied to every verb uniformly -- as it was -- the cut-off
    would return None and the agent would keep running, silently, at exactly
    the moment the operator decided it should not.
    """
    bot.rate_limit = 0.5                 # one message per 2s
    now = Clock()
    assert bot.handle(1, "status", now=now()) is not None
    assert bot.handle(1, "status", now=now()) is None, "limiter is engaged"
    assert bot.handle(1, "cut off", now=now()) is not None
    assert bot.kill.tripped(), "the cut-off went through the limiter and died"


def test_widening_is_refused_even_when_bound(bot):
    for cmd in ("allow rm:* at user", "grant sudo:*", "add task:1 ls:*"):
        r = bot.handle(1, cmd)
        assert r is not None
        assert "local-only" in r.text.lower(), cmd
    assert bot.store.grants().resolve(["rm", "-rf", "x"], user="u").verdict != "allow"


def test_every_local_only_action_is_refused_by_name(bot):
    """
    Iterating the constant, not a copy of it. This failed the first time
    because the bot kept its own hand-written list of refused verbs which had
    drifted: `edit_rails` answered "unknown command" and then printed the help.
    """
    for action in sorted(LOCAL_ONLY):
        r = bot.handle(1, action)
        assert r is not None and "local-only" in r.text.lower(), action


def test_rate_limit_silences_rather_than_errors(bot):
    bot.rate_limit = 0.5                 # one message per 2s
    now = Clock()
    assert bot.handle(1, "status", now=now()) is not None
    assert bot.handle(1, "status", now=now()) is None, "second message inside the window"
    assert bot.handle(1, "status", now=now.t + 10) is not None, "outside the window"


def test_approve_only_touches_an_existing_id(bot):
    rid = bot.store.request("task", "t1", "kubectl:*", "allow", justification="x")
    assert "approved" in bot.handle(1, f"approve {rid}").text
    r = bot.handle(1, "approve 9999")
    assert "9999" in r.text or "not" in r.text.lower()


def test_malformed_id_does_not_crash(bot):
    assert "usage" in bot.handle(1, "approve").text.lower()
    assert "usage" in bot.handle(1, "approve banana").text.lower()


def test_empty_message_is_silent(bot):
    assert bot.handle(1, "") is None
    assert bot.handle(1, "   ") is None


def test_unknown_command_answers_with_help(bot):
    assert "unknown" in bot.handle(1, "flurb").text.lower()


# -- transport -------------------------------------------------------------

def test_token_never_appears_in_a_send_failure(bot, capsys):
    t = Telegram("SECRET-TOKEN-123", bot, out=lambda *_: None)
    t.send(1, "hello")           # no network in tests: it raises and is caught
    err = capsys.readouterr()
    assert "SECRET-TOKEN-123" not in err.out + err.err


def test_pump_fails_open_when_telegram_is_unreachable(bot):
    """
    An unreachable Telegram must NOT stop the local path. This is the mirror
    of the rails, which fail closed -- and deliberately so.
    """
    t = Telegram("tok", bot, out=lambda *_: None, poll_interval=0.01)
    assert t.pump(once=True) == 0
    assert not bot.kill.tripped(), "a transport failure must not act on the agent"


def test_build_returns_none_without_a_token(tmp_path):
    from tool_judge.config import load as load_cfg
    from tool_judge.telegram import build
    assert build(load_cfg(env={}), GrantStore(tmp_path / "b.db")) is None

# -- a bad token is not a network blip -------------------------------------

class FakeHTTP(urllib.error.HTTPError):
    """An HTTPError that looks like a rejected token."""
    def __init__(self, code):
        super().__init__("https://api.telegram.org/botSECRET/bot", code,
                         "Unauthorized", None, None)


def test_rejected_token_is_distinguishable_from_a_blip(bot):
    """
    urllib raises HTTPError (a subclass of URLError) for a bad token, so the
    first version reported both the same way and exited 0 -- a supervisor
    watching that exit code sees a working remote control that is in fact
    incapable of cutting anything off.
    """
    t = Telegram("tok", bot, out=lambda *_: None, poll_interval=0)

    def refuse(*_a, **_kw):
        raise FakeHTTP(401)
    t._call = refuse

    assert t.pump(once=True) == 0, "must not act on the agent"
    assert not bot.kill.tripped()
    assert t.reachable is True, "Telegram answered -- this is not a blip"
    assert "401" in t.last_error


def test_unreachable_telegram_is_marked_unreachable(bot):
    t = Telegram("tok", bot, out=lambda *_: None, poll_interval=0)

    def offline(*_a, **_kw):
        raise urllib.error.URLError("no route")
    t._call = offline

    assert t.pump(once=True) == 0
    assert t.reachable is False
    assert not bot.kill.tripped()


def test_a_rejected_token_does_not_leak_into_the_send_log(bot, capsys):
    t = Telegram("SECRET-TOKEN-9", bot, poll_interval=0)

    def refuse(*_a, **_kw):
        raise FakeHTTP(401)
    t._call = refuse

    assert t.send(1, "hello") is False
    # `out` defaults to print, so the log lands on stdout.
    err = capsys.readouterr().out
    assert "SECRET-TOKEN-9" not in err
    assert "401" in err

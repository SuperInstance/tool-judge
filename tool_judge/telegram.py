"""
Telegram as a remote control, with the security properties that makes it one.

WHAT THIS IS NOT
----------------

A chat that can grant arbitrary permissions to a local shell. That is a weaker
boundary than a human at a terminal: it works from a phone, the audit trail
lives on someone else's server, and if agent context ever includes anything
from the channel then an injected instruction can arrive as a "message". See
LIMITS.md.

WHAT THIS IS
------------

A remote control for an agent you already trust, with the dangerous half
removed:

    cut off an agent      allowed. Fastest thing available.
    answer a pending id  allowed. Can only act on something that ALREADY
                         EXISTS -- it cannot invent a permission.
    widen anything       NOT ALLOWED. Ever. Not with the right secret, not
                         from the "right" account.

THE PROPERTIES THAT ACTUALLY MATTER
-----------------------------------

    binding      The first contact must present a shared secret. Without it,
                 anyone who finds the bot can bind it to their chat and then
                 stop every agent you run. Compared with hmac.compare_digest,
                 never `==`.

    allowlist    If TELEGRAM_ALLOWED_CHATS is set, only those chat ids are ever
                 served. Unbound chats get silence, not an error.

    no echo      Nothing this module sends includes the token, and errors are
                 truncated before they reach a chat. An exception message from
                 a transport can contain a URL.

    rate limit   Per chat. Not for security -- for the operator's attention,
                 because a bot that answers every message from a compromised
                 token is a bot you will mute, and then stop reading.

    fail closed on AUTHORISATION, fail open on INFORMATION

                 A bad secret gets nothing. An unreachable Telegram gets
                 nothing locally -- the local MCP keeps enforcing, which is
                 the whole reason the local path is the primary one.

TESTING WITHOUT A NETWORK

Transport and logic are separate. `handle_update()` is pure with respect to
the outside world; `transport()` is the only thing that touches the network
and it is the only thing that needs a token. The test suite drives
`handle_update()` directly and never opens a socket.
"""

from __future__ import annotations

import hmac
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .modes import LOCAL_ONLY, CutOff, KillSwitch

API = "https://api.telegram.org/bot{token}/{method}"

HELP = """\
tool-judge, from Telegram.

  status                 what the agent may do right now
  feed                   recent signals
  cut off [reason]       stop the agent (no confirmation)
  reset                  let it run again -- LOCAL ONLY, do it at a terminal
  approve <id> | deny <id>   answer a request that already exists

  Anything that would WIDEN an agent's permissions is refused here, on
  purpose. Granting more happens at the terminal.
"""


@dataclass
class Reply:
    text: str
    alert: bool = False


# How a human types a local-only action. The POLICY is modes.LOCAL_ONLY; this is
# only the spelling. Kept separate on purpose -- the first version of this file
# hardcoded its own list of refused verbs, it drifted from the constant, and
# `edit_rails` came back as "unknown command" plus the full help text.
_ALIASES = {
    "reset": "reset_kill_switch",
    "allow": "widen",
    "grant": "grant_new",
    "add": "grant_new",
    "rule": "edit_rails",
    "rules": "edit_rails",
}

# The verbs that stop an agent. Never rate limited -- see handle().
_KILL_VERBS = ("cut", "cut_off", "cutoff", "stop")


def _local_only(verb: str) -> str | None:
    """The LOCAL_ONLY action this verb names, or None if it names none."""
    name = verb.replace("-", "_")
    return name if name in LOCAL_ONLY else _ALIASES.get(name)


def _is_kill(verb: str) -> bool:
    return verb.replace("-", "_") in _KILL_VERBS


@dataclass
class Bot:
    """
    Logic half. No sockets, no token, no clock beyond `now` if injected.
    """
    store: object
    kill: KillSwitch
    bind_secret: str | None = None
    allowed_chats: tuple[int, ...] = ()
    rate_limit: float = 2.0
    bound_chats: set = field(default_factory=set)
    _last_seen: dict = field(default_factory=dict)

    # -- authorisation --------------------------------------------------

    def authorised(self, chat_id: int, text: str) -> bool:
        """
        Is this chat allowed to command the agent?

        An allowlist is ABSOLUTE and sufficient on its own: if
        TELEGRAM_ALLOWED_CHATS is set, membership is the credential and no
        shared secret is needed. The previous version demanded the secret on
        top of a listed chat, which contradicted config.validate() (which
        treats either as sufficient) and meant the allowlist bought nothing.

        With no allowlist, the first contact must present the shared secret.
        Compared with hmac.compare_digest, never `==`.
        """
        if self.allowed_chats:
            return chat_id in self.allowed_chats
        if chat_id in self.bound_chats:
            return True
        if self.bind_secret and hmac.compare_digest(text.strip(), self.bind_secret):
            self.bound_chats.add(chat_id)
            return True
        return False

    def rate_ok(self, chat_id: int, now: float) -> bool:
        last = self._last_seen.get(chat_id)
        if last is not None and now - last < (1.0 / max(self.rate_limit, 0.1)):
            return False
        self._last_seen[chat_id] = now
        return True

    # -- one message ----------------------------------------------------

    def handle(self, chat_id: int, text: str, *, now: float | None = None
               ) -> Reply | None:
        """
        Pure logic for one inbound message. Returns None to stay silent.

        Silence is a real answer here. An unrecognised chat, an unknown
        command and a rate-limited message all produce no output, because a
        bot that answers everything is a bot that tells a prober it is alive.
        """
        now = time.time() if now is None else now
        text = (text or "").strip()
        if not text:
            return None

        # Unbound chats get exactly one chance, and it has to be the secret.
        if not self.authorised(chat_id, text):
            return None

        verb, _, rest = text.partition(" ")
        verb = verb.lower().strip("/")

        # The rate limiter protects your attention, not the agent -- so it must
        # never swallow the command whose entire job is to stop things. The
        # first version throttled it like any other verb: tap "status" then
        # "cut off" inside half a second and the cut-off was dropped silently,
        # which is precisely the moment you need it to work.
        if not _is_kill(verb) and not self.rate_ok(chat_id, now):
            return None

        if self.bind_secret and hmac.compare_digest(text, self.bind_secret):
            return Reply("bound. commands: status, feed, cut off, approve, deny")

        if verb in ("help", "start", "?"):
            return Reply(HELP)
        if verb == "status":
            return Reply(self._status())
        if verb == "feed":
            return Reply(self._feed())
        if _is_kill(verb):
            self.kill.trip(rest.strip() or "cut off from telegram", by="telegram")
            return Reply(
                "stopped. every command is refused until you reset it from a "
                "terminal -- reset is deliberately not available from here.",
                alert=True)
        if verb in ("approve", "deny", "no"):
            return self._decide(verb, rest)
        action = _local_only(verb)
        if action:
            return Reply(
                f"'{action}' is local-only and will not run from a chat. "
                f"Local-only actions: {', '.join(sorted(LOCAL_ONLY))}. "
                f"Someone who can message this bot must not be able to give "
                f"your agents more power.", alert=True)
        return Reply(f"unknown: {verb}\n\n{HELP}")

    # -- command bodies --------------------------------------------------

    def _status(self) -> str:
        if self.kill.tripped():
            s = self.kill.state()
            return (f"CUT OFF since {time.strftime('%H:%M:%S', time.localtime(s.get('at', 0)))}"
                    f"{' — ' + s['reason'] if s.get('reason') else ''}\n"
                    f"reset from a terminal: tool-judge cut-off --reset")
        pending = self.store.pending()
        head = f"running. {len(pending)} request(s) waiting."
        return head + (f"\n  #{pending[0]['id']} {pending[0]['pattern']} "
                       f"({pending[0]['scope']}:{pending[0]['key']})"
                       if pending else "")

    def _feed(self) -> str:
        rows = self.store.pending("pending")
        if not rows:
            return "nothing pending."
        return "\n".join(f"#{r['id']} {r['pattern']}  {r['justification'][:44]}"
                         for r in rows)

    def _decide(self, verb: str, rest: str) -> Reply:
        try:
            rid = int((rest or "").strip().split()[0])
        except (ValueError, IndexError):
            return Reply(f"usage: {verb} <request-id>")
        approve = verb == "approve"
        try:
            out = self.store.decide(rid, approve, by="telegram")
        except (KeyError, ValueError) as exc:
            return Reply(str(exc)[:120])
        return Reply(
            f"#{out['id']} {out['status']}"
            + (f" -> {out['pattern']} at {out['scope']}" if approve else ""),
            alert=True)


# ---------------------------------------------------------------------------
# Transport. The only part that needs a token or a socket.
# ---------------------------------------------------------------------------

class Telegram:
    def __init__(self, token: str, bot: Bot, *, poll_interval: float = 2.0,
                 timeout: int = 25, out=print) -> None:
        self.token = token
        self.bot = bot
        self.poll_interval = poll_interval
        self.timeout = timeout
        self.out = out
        self._offset: int | None = None
        # Did the last poll fail? Distinguishes "Telegram is unreachable" from
        # "Telegram said no" -- urllib raises HTTPError (a subclass of
        # URLError) for a bad token, so the first version could not tell a
        # network blip from a token that will never work, and `--once` exited 0
        # for a bot that was never going to answer.
        self.last_error: str | None = None
        self.reachable: bool | None = None

    def _call(self, method: str, payload: dict | None = None) -> dict:
        req = urllib.request.Request(
            API.format(token=self.token, method=method),
            data=json.dumps(payload or {}).encode() if payload else None,
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout + 5) as r:
            return json.loads(r.read())

    def send(self, chat_id: int, text: str) -> bool:
        try:
            self._call("sendMessage", {"chat_id": chat_id, "text": text[:4000]})
            return True
        except urllib.error.HTTPError as exc:
            # Never echo the exception: transport errors embed the request URL,
            # and the request URL contains the token. The status code is safe.
            self.out(f"telegram send refused: HTTP {exc.code}")
            return False
        except (urllib.error.URLError, OSError, ValueError) as exc:
            self.out(f"telegram send failed: {type(exc).__name__}")
            return False

    def pump(self, once: bool = False) -> int:
        """
        Long-poll once. Returns the number of messages handled.

        Fails OPEN on transport problems: an unreachable Telegram must not stop
        the local path from working. That asymmetry is deliberate and is the
        opposite of what the rails do, because the rails are a verdict about
        the world and this is just a convenience channel.

        Fails LOUDLY, though, when Telegram answered and said no. A rejected
        token is not a blip, and a caller that exits 0 on one will sit there
        believing it has a remote control.
        """
        try:
            params = {"timeout": self.timeout}
            if self._offset is not None:
                params["offset"] = self._offset
            data = self._call("getUpdates", params)
        except urllib.error.HTTPError as exc:
            # Reached Telegram; it refused us. The code is safe to print --
            # the URL, and therefore the token, never is.
            self.reachable, self.last_error = True, f"HTTP {exc.code}"
            self.out(f"telegram refused the request: HTTP {exc.code}"
                     + ("  (check TELEGRAM_TOKEN)" if exc.code in (401, 404) else ""))
            if not once:
                time.sleep(self.poll_interval)
            return 0
        except (urllib.error.URLError, OSError, ValueError) as exc:
            self.reachable, self.last_error = False, type(exc).__name__
            self.out(f"telegram poll failed: {type(exc).__name__}")
            if not once:
                time.sleep(self.poll_interval)
            return 0

        self.reachable, self.last_error = True, None

        handled = 0
        for update in (data.get("result") or []):
            self._offset = update["update_id"] + 1
            msg = update.get("message") or {}
            chat_id = (msg.get("chat") or {}).get("id")
            text = msg.get("text", "")
            if not chat_id or not text:
                continue
            reply = self.bot.handle(chat_id, text)
            if reply is not None:
                self.send(chat_id, reply.text)
                handled += 1

        if not once:
            time.sleep(self.poll_interval)
        return handled

    def run(self) -> int:
        """
        Long-poll until interrupted. Returns an exit code.

        Gives up on a token Telegram has rejected. Retrying a 401 forever looks
        like a healthy process to anything watching it, and produces a bot that
        is silently incapable of cutting anything off.
        """
        self.out("telegram: long-polling. Ctrl-C to stop.")
        refused = 0
        while True:
            self.pump()
            if self.last_error and self.reachable:
                refused += 1
                if refused >= 3:
                    self.out("telegram: still refusing us after 3 tries. "
                             "Check TELEGRAM_TOKEN; stopping.")
                    return 2
            else:
                refused = 0


def build(cfg, store) -> Telegram | None:
    """Construct the transport from config, or None when Telegram is off."""
    if not cfg.telegram_token:
        return None
    return Telegram(
        cfg.telegram_token,
        Bot(store=store,
            kill=KillSwitch(cfg.kill_path),
            bind_secret=cfg.telegram_bind_secret,
            allowed_chats=cfg.telegram_allowed_chats,
            rate_limit=cfg.telegram_rate_limit),
    )
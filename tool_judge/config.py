"""
Configuration, validated rather than guessed.

The rule this file exists to enforce: **a missing key is not a default.**

Everything here either resolves to something that was explicitly supplied, or
fails with a message naming the variable and what it is for. Silently
defaulting a credential is how a system ends up talking to the wrong account,
and it is much harder to notice than a startup failure -- the failure is loud,
the default is not.

Layers, later wins:
    built-in defaults  ->  config file  ->  environment  ->  explicit flags

That order is deliberate. A file is for a human to edit and commit to nothing;
the environment is what a deployment injects and should therefore be able to
override what is checked in.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(RuntimeError):
    """Something required is missing or malformed. Loudly."""


DEFAULT_STORE = Path.home() / ".local/share/tool-judge/grants.db"
SESSION_ROOT = Path.home() / ".minimax" / "v2" / "sessions"
DECISION_URL = "http://127.0.0.1:11435"
DECISION_MODEL = "winnow:e4b"


@dataclass
class Config:
    # -- storage -------------------------------------------------------
    store: Path = DEFAULT_STORE
    rails: Path | None = None
    log_path: Path | None = None
    kill_path: Path | None = None

    # -- advisory judge (optional; absent means the gate degrades open) --
    decision_url: str | None = None
    decision_model: str = DECISION_MODEL

    # -- telegram (optional) -------------------------------------------
    telegram_token: str | None = None
    telegram_bind_secret: str | None = None
    telegram_allowed_chats: tuple[int, ...] = ()
    telegram_rate_limit: float = 2.0        # messages per second

    # -- transport guards ----------------------------------------------
    request_timeout: float = 60.0
    max_call_history: int = 64

    raw: dict = field(default_factory=dict)

    # -- derived --------------------------------------------------------

    @property
    def judge_enabled(self) -> bool:
        return bool(self.decision_url)

    @property
    def telegram_enabled(self) -> bool:
        return bool(self.telegram_token)

    def validate(self) -> list[str]:
        """
        Return problems. An empty list means usable.

        Deliberately non-fatal: a Telegram bot with no token and no decision
        server is a perfectly good local permission console, and refusing to
        start over a missing optional feature would be its own kind of wrong.
        Only genuinely incoherent settings raise.
        """
        problems: list[str] = []
        if not self.telegram_token and self.telegram_allowed_chats:
            problems.append(
                "TELEGRAM_ALLOWED_CHATS is set but TELEGRAM_TOKEN is not; "
                "the allowlist has nothing to apply to")
        if self.telegram_token and not self.telegram_bind_secret and not self.telegram_allowed_chats:
            problems.append(
                "TELEGRAM_TOKEN is set with neither TELEGRAM_BIND_SECRET nor "
                "TELEGRAM_ALLOWED_CHATS. Anyone who finds the bot can claim it "
                "and then cut your agents off. Set one of them.")
        if self.decision_url and not self.decision_url.startswith(("http://", "https://")):
            problems.append(f"DECISION_URL must be http(s), got {self.decision_url!r}")
        return problems

    def require_ok(self) -> None:
        problems = self.validate()
        if problems:
            raise ConfigError(
                "configuration is not usable:\n"
                + "\n".join(f"  - {p}" for p in problems))


def _load_file(path: Path | None) -> dict:
    if not path or not path.exists():
        return {}
    text = path.read_text()
    if path.suffix == ".json":
        return json.loads(text)
    # Minimal KEY=VALUE reader rather than a YAML dependency: this file is
    # meant to be readable by someone debugging a bot at midnight.
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        out[k.strip()] = v
    return out


def load(env: dict | None = None, *, file: Path | None = None,
         store: Path | None = None, rails: Path | None = None) -> Config:
    env = dict(os.environ if env is None else env)
    file = file or (Path(env["TOOL_JUDGE_CONFIG"]) if env.get("TOOL_JUDGE_CONFIG") else None)
    f = _load_file(file)

    def pick(name: str, default=None):
        # Environment beats file, so a deployment can override a committed one.
        return env.get(name, f.get(name, default))

    chats_raw = pick("TELEGRAM_ALLOWED_CHATS", "") or ""
    chats = tuple(int(c) for c in chats_raw.replace(",", " ").split() if c.strip().isdigit())

    store_path = Path(store or pick("TOOL_JUDGE_STORE") or DEFAULT_STORE)
    return Config(
        store=store_path,
        rails=Path(rails or pick("TOOL_JUDGE_RAILS")) if (rails or pick("TOOL_JUDGE_RAILS")) else None,
        log_path=Path(pick("TOOL_JUDGE_LOG") or store_path.with_suffix(".decisions.log")),
        kill_path=Path(pick("TOOL_JUDGE_KILL") or store_path.with_suffix(".kill.json")),
        decision_url=pick("DECISION_URL") or None,
        decision_model=pick("DECISION_MODEL", DECISION_MODEL),
        telegram_token=pick("TELEGRAM_TOKEN") or None,
        telegram_bind_secret=pick("TELEGRAM_BIND_SECRET") or None,
        telegram_allowed_chats=chats,
        telegram_rate_limit=float(pick("TELEGRAM_RATE", "2.0")),
        request_timeout=float(pick("TOOL_JUDGE_TIMEOUT", "60")),
        raw={"file": str(file) if file else None},
    )


def describe(cfg: Config) -> str:
    """
    Print the configuration WITHOUT the secrets.

    There is a real temptation to log the resolved config on startup, and the
    one line that must never be in it is the bot token. Names and presence
    only.
    """
    def yn(v) -> str:
        return "set" if v else "-"
    return "\n".join([
        "configuration:",
        f"  store            {cfg.store}",
        f"  rails            {cfg.rails or '(none)'}",
        f"  decision server  {cfg.decision_url or '(disabled)'} "
        f"[{cfg.decision_model}]",
        f"  telegram         {yn(cfg.telegram_token)}"
        + (f", chats={list(cfg.telegram_allowed_chats) or '(bind on first use)'}"
           if cfg.telegram_token else ""),
        f"  bind secret      {yn(cfg.telegram_bind_secret)}",
        f"  judge enabled    {cfg.judge_enabled}",
        f"  telegram enabled {cfg.telegram_enabled}",
    ])
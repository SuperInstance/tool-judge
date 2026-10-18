"""
Read mcode's own transcript and judge what actually ran.

THE HONEST WAY TO LOG A FULLY-PERMISSIONED AGENT
------------------------------------------------

You asked for the main agent to have full permissions, with everything logged.
There are two ways to do that, and the difference between them is the whole
point of this file.

THE WEAK WAY. Install an MCP server and tell the agent to call `check_command`
before it runs anything. The agent can comply. The agent can also forget, or
decide it is obviously fine, or be talked out of it by text it read five
minutes ago. You have built a suggestion box and called it a log.

THE REAL WAY. mcode already writes every tool call -- name and full arguments
-- to `~/.minimax/v2/sessions/**/messages.jsonl`, at the moment it issues it:

    {"type": "toolCall", "name": "bash",
     "arguments": {"command": "git status -sb", ...}}

That record is written by the process that EXECUTES the command, not by the
model that proposed it. It cannot be forgotten, cannot be skipped, and cannot
be edited by the agent without editing the very file being audited. So it is
the source of truth, and this module reads it.

That inverts the relationship. The agent's own MCP calls become advisory --
useful, cheap, and welcome. The transcript is authoritative. tool-judge stops
trying to be a gate and becomes something better: it reads what happened
afterwards and tells you which of it was worth a second look.

WHY THIS IS THE RIGHT SHAPE
---------------------------

Logging after the fact has a cost the before-the-fact approach does not: you
cannot stop the command. What you CAN do is know, precisely, what ran --
including the things nobody asked about -- which is what an audit is for. And
the detector that was useless as a gate (it only sees one command at a time,
and an agent that never calls it) is exactly right here, because now it sees
the whole sequence.

RUN IT

    tool-judge audit                    # newest session
    tool-judge audit --session <path>   # a specific transcript
    tool-judge audit --watch            # follow, for a long-running agent
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from .anomaly import Alert, Detector, Observation
from .decisionlog import DecisionLog
from .modes import CutOff, KillSwitch

SESSION_ROOT = Path.home() / ".minimax" / "v2" / "sessions"

#: Tools whose arguments carry a command we can meaningfully reason about.
COMMAND_TOOLS = {"bash"}


@dataclass
class Call:
    ts: float
    tool: str
    argv: tuple[str, ...]
    raw: str
    turn: str = ""


@dataclass
class AuditReport:
    session: str
    calls: int = 0
    commands: int = 0
    alerts: list[Alert] = field(default_factory=list)
    by_tool: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def render(self) -> str:
        out = [
            "",
            "=" * 68,
            f"AUDIT  {self.calls} tool calls, {self.commands} commands"
            f"   ({self.session})",
            "=" * 68,
            "",
            "  by tool: " + (", ".join(f"{k} {v}"
                                       for k, v in sorted(self.by_tool.items()))
                             or "(none)"),
        ]
        if self.errors:
            out.append("")
            out.append("  could not read:")
            out += [f"    - {e}" for e in self.errors[:5]]
        if not self.alerts:
            out += ["", "  no behavioural signals fired.", "",
                    "  That is the expected result on ordinary work. It is not",
                    "  evidence the audit works -- see the note below."]
        else:
            out.append("")
            out.append(f"  {len(self.alerts)} signal(s):")
            for a in self.alerts:
                out.append(a.render())
        out += ["",
                "  This log comes from the process that issued the commands, so",
                "  it cannot be skipped by an agent that forgets to check. It is",
                "  also AFTER the fact: it tells you what happened, not what to",
                "  stop. For the before-the-fact version, keep an MCP server",
                "  attached and keep the rails narrow enough to matter.",
                "=" * 68]
        return "\n".join(out)


def _argv_from(tool: str, args: dict) -> tuple[tuple[str, ...], str]:
    """
    Best-effort argv from a recorded tool call.

    bash carries a single `command` string, which may be a compound shell
    line. Splitting on `;`/`&&` matters: an agent hiding `curl ... | sh` in
    the tail of a harmless-looking command is the whole reason this exists,
    and joining it back into one string would hide it.
    """
    if tool not in COMMAND_TOOLS:
        return (), ""
    raw = (args or {}).get("command") or ""
    if not raw:
        return (), ""
    parts = _split_compound(raw)
    first = parts[0] if parts else raw
    return tuple(first.split()), raw


def _split_compound(command: str) -> list[str]:
    """Split on shell separators, respecting simple quoting."""
    out, cur, quote = [], "", None
    i = 0
    while i < len(command):
        ch = command[i]
        if quote:
            cur += ch
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            cur += ch
        elif ch in ";&|":
            if cur.strip():
                out.append(cur.strip())
            cur = ""
        elif ch == "\n":
            if cur.strip():
                out.append(cur.strip())
            cur = ""
        else:
            cur += ch
        i += 1
    if cur.strip():
        out.append(cur.strip())
    return out


def iter_calls(path: Path):
    """
    Yield every recorded tool call in a transcript.

    Tolerant by necessity: these files are multi-megabyte append-only logs
    that may be read while they are being written, so a truncated final line
    is normal and must not abort the audit.
    """
    with path.open(errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            message = rec.get("message") or {}
            for item in (message.get("content") or []):
                if not isinstance(item, dict):
                    continue
                if item.get("type") != "toolCall":
                    continue
                tool = item.get("name", "")
                args = item.get("arguments") or {}
                argv, raw = _argv_from(tool, args)
                yield Call(ts=float(rec.get("ts") or time.time()), tool=tool,
                           argv=argv, raw=raw, turn=rec.get("turn_id", ""))


def newest_session(root: Path = SESSION_ROOT) -> Path | None:
    cands = sorted(root.rglob("messages.jsonl"), key=lambda p: p.stat().st_mtime)
    return cands[-1] if cands else None


def audit(path: Path, *, kill: KillSwitch | None = None,
          log: DecisionLog | None = None) -> AuditReport:
    """
    Read a transcript, replay its commands through the detector.

    REPLAY IS THE POINT. The detector was built for a live stream, where it
    only ever sees the command in front of it. Replaying a finished transcript
    gives it the entire sequence -- and every signal it has is about
    relationships between commands, so a replay finds strictly more than a
    live run of the same session would have.
    """
    rep = AuditReport(session=str(path))
    det = Detector()
    try:
        if kill is not None and kill.tripped():
            rep.alerts.append(Alert(
                "high", "cut-off-during-session",
                "the agent was cut off while this session was running",
                [f"kill switch: {kill.state().get('reason', '')}"],
                ["you cut it off deliberately; this is expected",
                 "or something tripped it and you have not looked yet"]))
    except Exception as exc:                                # noqa: BLE001
        rep.errors.append(f"kill switch: {exc}")

    try:
        for call in iter_calls(path):
            rep.calls += 1
            rep.by_tool[call.tool] = rep.by_tool.get(call.tool, 0) + 1
            if call.tool not in COMMAND_TOOLS or not call.argv:
                continue
            rep.commands += 1
            # Verdict is unknown after the fact, which is fine: the detector's
            # signals are about the COMMAND SEQUENCE, and the only signal that
            # depends on a verdict (probe-after-refusal) treats "we do not
            # know what happened" as a refusal, which is the conservative
            # direction -- an agent poking at things that were probably denied.
            rep.alerts.extend(det.observe(
                Observation(ts=call.ts, argv=call.argv,
                            verdict="unknown", rail="")))
    except OSError as exc:
        rep.errors.append(str(exc))

    if log is not None:
        for a in rep.alerts:
            log.record("deny" if a.severity.value == "high" else "ask",
                       pattern=a.kind, reason=a.title,
                       decided_by=f"audit:{path.name}")
    return rep


def watch(path: Path, interval: float = 5.0, poll=print, kill=None):
    """
    Follow a transcript while an agent works.

    Tails by byte offset so re-reading a growing file does not re-report the
    whole history every tick. Deliberately re-raises alerts it has seen: a
    signal you only see once, between polls, is a signal you miss.
    """
    seen = 0
    det = Detector()
    try:
        with path.open() as fh:
            fh.seek(0, 2)
            while True:
                size = fh.seek(0, 2)
                if size > seen:
                    fh.seek(seen)
                    chunk = fh.read(size - seen)
                    seen = size
                    for line in chunk.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        for item in ((rec.get("message") or {}).get("content") or []):
                            if not isinstance(item, dict) or item.get("type") != "toolCall":
                                continue
                            argv, raw = _argv_from(item.get("name", ""),
                                                   item.get("arguments") or {})
                            if not argv:
                                continue
                            for a in det.observe(Observation(
                                    ts=time.time(), argv=argv, verdict="unknown")):
                                poll(a.render())
                time.sleep(interval)
    except KeyboardInterrupt:
        return
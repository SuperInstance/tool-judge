"""
Goal-fit judge: how well does this command belong to this project?

Sibling to cycle-judge, same idiom -- one shot, no chain of thought, a small
decision model on a local server. Different subject: cycle-judge asks whether
an agent's *claim* about its work is true; this asks whether a *command*
belongs to the project.

    >>> GoalFitJudge(spec=spec).check(["kubectl", "delete", "ns", "prod"])
    {'verdict': 'allow', 'score': 0.21, 'band': 'off_goal',
     'annotation': "unrelated to this project", 'degraded': False}

THE SPLIT THAT MAKES THIS HONEST
-------------------------------

    rails    deterministic, no model, no network. ENFORCES.
    goalfit  a model, may be wrong, no guarantee. ADVISES.

Conflating them is how a safety layer becomes an unreliable one. An agent
that asks a language model whether it may run `rm -rf` has built a suggestion
box where it needed a wall. `rails.py` is the wall. This is the label on the
door.

FOUR THINGS IT CANNOT DO
-------------------------

1. It cannot tell you a command is safe. Only rails can. A model reading
   "never delete from GitHub" is not a guarantee; a deny rule is.
2. It will be wrong. It is a 4B model, one shot, a few hundred words of
   context. Fast and cheap is the trade and the trade is real.
3. It is not a security boundary. Anything it approves could equally be
   approved by no judge at all.
4. Its value is narrow: it catches the mismatch between what the project IS
   and what this command DOES -- coherent commands that are simply not this
   project's business. That is coherence, not safety.

HOW IT FAILED THE FIRST TIME, because the failure is the design lesson
-----------------------------------------------------------------------

This module was first pointed at Ollama's `/api/generate`. The decision server
does not implement it, so every call returned HTTP 404. A gate fails open, so
every call returned `fits @ 0.00`.

    Four identical, confident-looking verdicts. Total outage.

That is precisely the failure this tool exists to catch in other software, and
it happened in the tool written to catch it. Two consequences are baked in:

  - `degraded_count` counts every fallback, so "everything degraded" can never
    again be mistaken for "everything agreed".
  - `check()` reports `degraded` per call, and the CLI prints it.

Fail-open is a posture. Fail-silent is a bug. They are different.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

DEFAULT_URL = "http://127.0.0.1:11435"
DEFAULT_MODEL = "winnow:e4b"

# Found by examples/probe_decisions_api.py against a running server.
#
# The type is `noul` -- the ranking-only question type -- and it returns ONE
# SCALAR, not a choice plus a confidence. That is the right tool here and the
# distinction matters:
#
#   a `choice` question makes the model COMMIT to a category
#   a `noul` question makes the model RANK without committing
#
# Goal-fit is a ranking. The honest answer is usually "less well than the
# things that obviously fit", not "definitely foreign". Asking a 4B model to
# commit to a category makes it certain about something it should only sort.
# It also means there is no confidence value, so this module does not
# pretend to have one -- an earlier version invented one and it was always 0.
#
# Response shape, verbatim:
#     {"answers": {"goal_fit": {"type": "noul", "noul": 0.5712}}}
QUESTION = {
    "type": "noul",
    "noul": {
        "criteria": {
            "id": "goal_fit",
            "prompt": "How well does this command belong to this project's work?",
        }
    },
}

# Bands over the scalar. Deliberately coarse: a 4B model cannot resolve 0.55
# from 0.58, and pretending otherwise manufactures precision that is not there.
BANDS = ((0.66, "fits"), (0.33, "uncertain"), (0.0, "off_goal"))

ANNOTATIONS = {
    "fits": None,
    "uncertain": "may not belong to this project",
    "off_goal": "unrelated to this project's work",
}


def band(score: float) -> str:
    for threshold, label in BANDS:
        if score >= threshold:
            return label
    return "off_goal"


@dataclass
class Fit:
    score: float
    band: str
    annotation: str | None
    degraded: bool = False
    reason: str = ""

    def __str__(self) -> str:
        s = f"{self.band}@{self.score:.2f}"
        if self.degraded:
            s += f" (DEGRADED: {self.reason})"
        if self.annotation:
            s += f"  [{self.annotation}]"
        return s


class GoalFitJudge:
    def __init__(self, url: str = DEFAULT_URL, spec=None,
                 model: str = DEFAULT_MODEL, timeout: float = 60.0,
                 question: dict | None = None) -> None:
        self.url = url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.spec = spec
        self.question = question if question is not None else dict(QUESTION)
        # Loud accounting for the fail-open path. See the module docstring.
        self.degraded_count = 0

    # -- context --------------------------------------------------------

    @property
    def context(self) -> str:
        return self.spec.context_digest() if self.spec else ""

    # -- transport ------------------------------------------------------

    def available(self) -> bool:
        try:
            with urllib.request.urlopen(f"{self.url}/api/tags", timeout=5) as r:
                body = json.loads(r.read())
            return any(m.get("name", "").split(":")[0] == self.model.split(":")[0]
                       for m in body.get("models", []))
        except (urllib.error.URLError, OSError, ValueError, TimeoutError):
            return False

    def _degrade(self, reason: str) -> Fit:
        self.degraded_count += 1
        return Fit(0.0, "unknown", None, degraded=True, reason=reason)

    # -- the question ----------------------------------------------------

    def fit(self, command: str) -> Fit:
        if not self.context.strip():
            return self._degrade("no project context supplied")

        payload = {
            "model": self.model,
            "state": {"project_context": self.context, "command": command},
            "questions": {"goal_fit": dict(self.question)},
        }
        try:
            req = urllib.request.Request(
                f"{self.url}/v1/decisions",
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = json.loads(r.read())
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read().decode()[:160]
            except Exception:                                   # noqa: BLE001
                detail = ""
            return self._degrade(f"HTTP {exc.code} {detail}")
        except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
            # FAIL OPEN. A gate that fails shut on a model hiccup halts work.
            return self._degrade(f"unreachable: {type(exc).__name__}")

        answers = body.get("answers") if isinstance(body, dict) else None
        entry = answers.get("goal_fit") if isinstance(answers, dict) else None
        if not isinstance(entry, dict) or "noul" not in entry:
            return self._degrade("no noul answer for goal_fit")
        try:
            score = float(entry["noul"])
        except (TypeError, ValueError):
            return self._degrade("non-numeric noul")
        score = max(0.0, min(1.0, score))

        b = band(score)
        return Fit(score, b, ANNOTATIONS[b])

    # -- full answer ------------------------------------------------------

    def check(self, argv: list[str]) -> dict[str, Any]:
        """
        Rails first, then goal-fit. Rails are consulted BEFORE the model is
        spent, so a denied command never gets the judge's blessing and never
        costs a call. That ordering is the security property.
        """
        if not isinstance(argv, (list, tuple)) or not argv:
            return {"verdict": "deny", "reason": "empty command",
                    "rail": "malformed", "annotation": None}

        if self.spec is None:
            # No rails means no floor. Say so rather than silently judging.
            return {"verdict": "ask", "reason": "no rails bound to this judge",
                    "rail": None, "annotation": None}

        d = self.spec.checker().check(list(argv))
        if d.verdict.value in ("deny", "ask"):
            # Rails answered. The judge is not consulted, by design.
            return {"verdict": d.verdict.value, "reason": d.reason,
                    "rail": d.rail, "annotation": None,
                    "goal_fit": None, "degraded": False}

        f = self.fit(" ".join(argv))
        return {"verdict": d.verdict.value, "reason": d.reason, "rail": d.rail,
                "goal_fit": {"score": f.score, "band": f.band},
                "annotation": f.annotation, "degraded": f.degraded,
                "degraded_reason": f.reason or None}
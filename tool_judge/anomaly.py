"""
Behavioural detection: the command was allowed, and that is the problem.

A permission layer answers one question -- may this run? -- and a compromised
agent's first problem is that many of its attempts are perfectly legal. It has
a token, it has a shell, and `git status` is permitted. Nothing fires. The
agent then tries the next thing, and the next, and the interesting behaviour is
in the SEQUENCE rather than in any single command.

This module watches the sequence.

THE PRIMARY SIGNAL: PROBING AFTER A REFUSAL
-------------------------------------------

This is the one worth building first, because it is the signature of a
compromised agent and it contradicts a rule this project already wrote:

    "A refused command is a decision, not an obstacle to route around."
                                                  -- LIMITS.md

An agent that is reasoning about a refusal, or working around one, produces a
recognisable trace:

    rm  -rf  /tmp/x     DENY   ->  rm  /tmp/x     ->  rm  -f  /tmp/x
    sudo apt install    DENY   ->  doas apt install
    kubectl delete ns   DENY   ->  kubectl delete namespace

Same program, same intent, different spelling. Each variant is individually
innocuous enough to pass. Together they are the agent looking for the gap in
your rules, which is exactly what an injected "ignore previous instructions
and clean up" turns into.

The escalation ladder is the same shape: `rm <file>` then `rm -r <dir>` then
`rm -rf <dir>`. Each step is a real thing an agent might do. The ladder is not.

WHAT THIS IS NOT
----------------

It is not a claim that the agent is compromised. It is a claim that a
*particular pattern* appeared, with the evidence attached, for a human to judge.

That restraint is deliberate and load-bearing. A guard that cries wolf gets
dismissed, and a dismissed guard is worse than no guard, because it teaches
the human that this class of signal is noise. Every alert here carries its
evidence and its alternative explanation -- benign causes are named, because
they are usually the true cause and the human needs to tell them apart in
seconds.
"""

from __future__ import annotations

import re
import shlex
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    WARN = "warn"
    HIGH = "high"


@dataclass(frozen=True)
class Observation:
    """One command the agent tried, and what happened to it."""
    ts: float
    argv: tuple[str, ...]
    verdict: str            # allow | ask | deny | unlisted
    scope: str = ""
    rail: str = ""
    agent: str = "agent"


def program(argv) -> str:
    return argv[0] if argv else ""


#: Programs whose first non-flag argument is a SUBCOMMAND rather than data.
#: Without this, `git status -sb` and `git commit -m x` share a signature and
#: every git session looks like probing.
SUBCOMMAND_PROGRAMS = frozenset({
    "git", "gh", "kubectl", "docker", "npm", "pnpm", "yarn", "cargo", "pip",
    "systemctl", "brew", "apt", "dnf", "helm", "terraform", "aws", "gcloud",
    "supervisorctl", "journalctl", "tool-judge", "zcode", "mcode", "uv",
})


def operation(argv) -> tuple[str, ...]:
    """
    Which operation is this? Program, plus subcommand where one exists.

    This is the fix for the false positive that made every git session look
    like probing: `git status` and `git commit` are unrelated operations, so
    running one after the other is not an agent looking for a gap in the rules.
    `rm` has no subcommand, so `rm -rf x` and `rm -r x` are the same operation
    with different severity -- which is the case worth flagging.
    """
    prog = program(argv)
    if prog in SUBCOMMAND_PROGRAMS:
        for a in argv[1:]:
            if not a.startswith("-"):
                return (prog, a)
    return (prog,)


def _norm(argv) -> str:
    """
    Command signature: the operation, plus its flags.

    `rm -rf /tmp/a` and `rm -f /tmp/b` reduce to the same thing -- the agent is
    still operating on the same tool. Data arguments are deliberately dropped;
    the question is "is it still poking the same operation", not "with what".
    """
    return " ".join([*operation(argv),
                     *sorted(a for a in argv[1:] if a.startswith("-"))])


def _danger_rank(argv) -> int:
    """
    How destructive is this invocation, on a crude ladder?

    Only used to detect escalation, and deliberately coarse. The point is
    monotone *shape*, not an accurate damage model -- an accurate one is the
    rails' job and they do it far better.
    """
    args = " ".join(argv)
    score = 0
    if re.search(r"(^|\s)-{1,2}[a-z]*r[a-z]*(\s|$)|recursive", args):
        score += 2
    if re.search(r"(^|\s)-{1,2}[a-z]*f[a-z]*(\s|$)|force", args):
        score += 2
    if "/" in args:
        score += 1
    if argv[:1] and argv[0] in ("sudo", "doas", "su"):
        score += 5
    return score


#: Verdicts that count as "this did not go through" when correlating attempts.
#:
#: `unknown` is NOT in this list, which it briefly was. An audit replay reads a
#: finished transcript: it knows what ran but not what any gate said at the
#: time, and adding "unknown" so the probe signal would fire on a replay
#: produced THREE alerts on a real 370-call session -- all of them false:
#: `ls -la` on four different directories while exploring, and running
#: `--check` before `--apply`. Three for three.
#:
#: Treating unknown as a refusal is not conservative, it is FABRICATING
#: evidence. The fix is a different signal, not a looser one: `target_ramp`
#: needs no verdict at all, because it is about what an agent did rather than
#: what it was told.
REFUSAL_LIKE = ("deny", "ask")

#: Programs with a well-known privilege-equivalent. Used to catch the
#: "same capability, different binary" rewrite, which is otherwise invisible.
PRIVILEGE_EQUIVALENTS = {
    "sudo": "root", "doas": "root", "su": "root", "pkexec": "root",
}


@dataclass
class Alert:
    severity: Severity
    kind: str
    title: str
    evidence: list[str]
    benign_explanations: list[str]
    detected_at: float = field(default_factory=time.time)

    def render(self) -> str:
        s = [f"[{self.severity.value.upper()}] {self.title}"]
        if self.evidence:
            s.append("  what happened:")
            s += [f"    {e}" for e in self.evidence]
        if self.benign_explanations:
            s.append("  this is usually one of:")
            s += [f"    - {b}" for b in self.benign_explanations]
        return "\n".join(s)


class Detector:
    """
    Watches a sequence of observations and raises alerts.

    Stateful by necessity -- every signal here is about relationships between
    observations, which is also why it cannot be a pure function and why it is
    the part most likely to need calibration against a real corpus.
    """

    #: How many observations to remember. Short on purpose: probing happens in
    #: bursts, and a long memory would fire on unrelated work hours later.
    WINDOW = 12

    def __init__(self, window: int = WINDOW) -> None:
        self.history: deque[Observation] = deque(maxlen=window)

    def observe(self, obs: Observation) -> list[Alert]:
        self.history.append(obs)
        alerts: list[Alert] = []
        alerts += self._probe_after_refusal(obs)
        alerts += self._privilege_rewrite(obs)
        alerts += self._escalation_ladder(obs)
        alerts += self._target_ramp(obs)
        return alerts

    # -- signals --------------------------------------------------------

    def _recent(self, n: int = 6) -> list[Observation]:
        return list(self.history)[-n:]

    def _probe_after_refusal(self, obs: Observation) -> list[Alert]:
        """
        Same program, retried after a refusal, with different spelling.

        The high-severity signal. A refusal is information the agent did not
        have, and an agent that has been injected will spend it.

        Note what is NOT required: the retry does not have to be refused
        again. The interesting case is the opposite -- the first spelling is
        refused and the next one SUCCEEDS, which is the agent finding the gap
        in the rules rather than running into it. Gating this on the current
        verdict would miss exactly the case worth catching, which is what the
        first version of this method did.
        """
        prior_refusals = [o for o in self._recent(8)[:-1]
                          if o.verdict in REFUSAL_LIKE
                          and operation(o.argv) == operation(obs.argv)
                          and _norm(o.argv) != _norm(obs.argv)]
        if not prior_refusals:
            return []

        chain = prior_refusals + [obs]
        evidence = [f"{o.verdict.upper():<7} {' '.join(o.argv)}" for o in chain]
        # Severity is decided by whether the retry GOT THROUGH, not by whether
        # it was refused again. A refusal followed by a different spelling
        # that is then ALLOWED is the rules failing to hold; a refusal
        # followed by a different spelling that is refused again is the agent
        # being stuck, which is annoying rather than dangerous. The first
        # version of this had those backwards.
        return [Alert(
            Severity.HIGH if obs.verdict == "allow" else Severity.WARN,
            "probe-after-refusal",
            f"{program(obs.argv)} was refused {len(prior_refusals)}x and is "
            f"being retried differently",
            evidence,
            [
                "a human is trying the same thing by hand in another terminal",
                "an agent is adapting to a flag the rail did not match, "
                "without understanding why it was refused",
                "a build script retries with reduced flags on first failure",
            ])]

    def _privilege_rewrite(self, obs: Observation) -> list[Alert]:
        """
        `sudo` refused, then the same request via an equivalent binary.

        Invisible to a pattern list that only knows the word "sudo".
        """
        priv = PRIVILEGE_EQUIVALENTS.get(program(obs.argv))
        if not priv:
            return []
        prior = [o for o in self._recent(8)[:-1]
                 if PRIVILEGE_EQUIVALENTS.get(program(o.argv)) == priv
                 and program(o.argv) != program(obs.argv)
                 and o.verdict in ("deny", "ask")]
        if not prior:
            return []
        return [Alert(
            Severity.HIGH, "privilege-rewrite",
            f"a different binary requesting the same privilege as "
            f"{' '.join(prior[-1].argv)}",
            [f"{o.verdict.upper():<7} {' '.join(o.argv)}" for o in prior + [obs]],
            ["the agent is picking whichever escalation tool is installed",
             "a script has its own sudo-to-doos fallback"],
        )]

    @staticmethod
    def _target(argv) -> str:
        """The thing being acted on: the last non-flag argument."""
        vals = [a for a in argv[1:] if not a.startswith("-")]
        return vals[-1] if vals else ""

    def _target_ramp(self, obs: Observation) -> list[Alert]:
        """
        Same operation, SAME TARGET, climbing in destructiveness.

        This is the signal that survives an audit replay, because it needs no
        verdict -- it is about what the agent DID, not what it was told.
        Exploring with `ls` across four directories does not fire: the targets
        differ. `rm -rf data`, `rm -r data`, `rm -f data` does: one target,
        three attempts, each a step back from the most destructive.

        Needing the target to match is what separates this from ordinary
        variation. Without it, every repeated invocation of any program looks
        like escalation, which is what the first version of this file did.
        """
        prog = program(obs.argv)
        rank = _danger_rank(obs.argv)
        target = self._target(obs.argv)
        if rank < 2 or not target:
            return []
        same = [o for o in self._recent(6)[:-1]
                if program(o.argv) == prog
                and self._target(o.argv) == target
                and _norm(o.argv) != _norm(obs.argv)]
        if not same:
            return []
        return [Alert(
            Severity.WARN if obs.verdict != "allow" else Severity.HIGH,
            "target-ramp",
            f"{prog} was aimed at {target!r} {len(same)} more time(s), each "
            f"differently",
            [f"{o.verdict.upper():<7} {' '.join(o.argv)}" for o in same + [obs]],
            ["an agent working out how to address one path or resource",
             "a tool retrying with a different flag after a partial failure"],
        )]

    def _escalation_ladder(self, obs: Observation) -> list[Alert]:
        """
        The same destructive program climbing a damage ladder.

        `rm f` -> `rm -r d` -> `rm -rf d` is three ordinary commands and one
        alarming sequence.
        """
        prog = program(obs.argv)
        if prog in ("rm", "shred", "mv") and obs.verdict != "allow":
            return []
        rank = _danger_rank(obs.argv)
        if rank < 2:
            return []

        same = [o for o in self._recent(6)[:-1]
                if program(o.argv) == prog and _danger_rank(o.argv) < rank]
        if not same:
            return []
        return [Alert(
            Severity.WARN, "escalation-ladder",
            f"{prog} was used more destructively than {len(same)} time(s) "
            f"recently",
            [f"{o.verdict.upper():<7} {' '.join(o.argv)}"
             for o in same + [obs]],
            ["a cleanup pass that got broader than intended",
             "the agent is following a script whose flags grew"],
        )]
"""
The rails must actually refuse things.

A safety layer's tests are not interesting when they pass — they are
interesting when you have seen them fail. So this file is built around one
idea: a named corpus of commands, each labelled with the verdict it MUST
produce, checked as a table. Adding a command is one line. Missing a verdict
is a red test, not a judgement call.

The corpus includes the commands that would do real damage, in more than one
spelling. Spelling is the attack surface: `rm -rf`, `rm  -rf`, `/bin/rm -rf`
and `rm --recursive --force` are the same catastrophe, and a rail that
matches only the first is decoration.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tool_judge import Verdict, load            # noqa: E402
from tool_judge.rails import Pattern            # noqa: E402
from tool_judge.spec import SpecError           # noqa: E402

RAILS = ROOT / "rails" / "g1-ble-backend.yaml"


@pytest.fixture(scope="module")
def spec():
    return load(RAILS)


# ---------------------------------------------------------------------------
# THE CORPUS
# (argv, expected verdict, which rail if not allow)
# ---------------------------------------------------------------------------

CORPUS = [
    # -- refusals: the operator's two stated constraints ------------------
    (["git", "push", "origin", "main", "--force"], Verdict.DENY, "no-force-push"),
    (["git", "push", "--force-with-lease", "origin", "main"], Verdict.DENY, "no-force-push"),
    (["git", "push", "-f", "origin", "main"], Verdict.DENY, "no-force-push"),
    (["git", "push", "origin", "+main"], Verdict.DENY, "no-force-push"),
    (["git", "reset", "--hard", "HEAD~3"], Verdict.DENY, "no-destroy-local-history"),
    (["git", "clean", "-fdx"], Verdict.DENY, "no-destroy-local-history"),
    (["git", "clean", "-fd"], Verdict.DENY, "no-destroy-local-history"),
    (["git", "branch", "-D", "experiment"], Verdict.DENY, "no-destroy-local-history"),
    (["gh", "repo", "delete", "SuperInstance/g1-ble-backend"], Verdict.DENY, "no-github-deletion"),
    (["gh", "repo", "delete", "SuperInstance/g1-ble-backend", "--yes"], Verdict.DENY, "no-github-deletion"),
    (["gh", "api", "-X", "DELETE", "repos/x/y"], Verdict.DENY, "no-github-deletion"),
    (["gh", "api", "--method", "DELETE", "repos/x/y"], Verdict.DENY, "no-github-deletion"),
    (["gh", "secret", "delete", "API_KEY"], Verdict.DENY, "no-github-deletion"),
    (["sudo", "rm", "/var/lib/thing"], Verdict.DENY, "no-privilege-escalation"),
    (["rm", "-rf", "/home/proart/projects/glasses"], Verdict.DENY, "no-bare-rm"),
    (["rm", "-fr", "src"], Verdict.DENY, "no-bare-rm"),
    (["rm", "-f", "/etc/passwd"], Verdict.DENY, "no-bare-rm"),

    # -- escalate: hardware and secrets -----------------------------------
    (["bluetoothctl", "scan", "on"], Verdict.ASK, "live-hardware-needs-human"),
    (["btmon"], Verdict.ASK, "live-hardware-needs-human"),
    (["git", "add", ".env"], Verdict.ASK, "no-secret-commit"),
    (["git", "add", "config/credentials.yaml"], Verdict.ASK, "no-secret-commit"),
    (["git", "push", "origin", "main"], Verdict.ASK, "git-push"),

    # -- allowed: the ordinary vocabulary ---------------------------------
    (["ls", "-la"], Verdict.ALLOW, None),
    (["cat", "README.md"], Verdict.ALLOW, None),
    (["grep", "-rn", "pattern", "."], Verdict.ALLOW, None),
    (["sed", "-n", "1,20p", "file.py"], Verdict.ALLOW, None),
    (["git", "status", "-sb"], Verdict.ALLOW, None),
    (["git", "diff", "--stat"], Verdict.ALLOW, None),
    (["git", "commit", "-m", "fix the thing"], Verdict.ALLOW, None),
    (["gh", "pr", "list"], Verdict.ALLOW, None),
    (["python3", "scripts/build.py"], Verdict.ALLOW, None),
    ([".venv/bin/python", "experiments/store_stress.py"], Verdict.ALLOW, None),

    # -- unlisted: ASK, not ALLOW ------------------------------------------
    # The load-bearing case. Nothing about an unlisted command says it is
    # safe; it says nobody has decided yet.
    (["terraform", "apply"], Verdict.ASK, None),
    (["kubectl", "delete", "pod", "x"], Verdict.ASK, None),
    (["docker", "push", "private/thing"], Verdict.ASK, None),
]


@pytest.mark.parametrize("argv,expected,rail", CORPUS,
                         ids=[f"{c[0][0]}…{c[0][-1]}" for c in CORPUS])
def test_verdict(spec, argv, expected, rail):
    d = spec.checker().check(argv)
    assert d.verdict is expected, f"{argv} -> {d}"
    if rail:
        assert d.rail == rail, f"{argv} -> {d}"


def test_deny_beats_allow(spec):
    """
    A broad allow must not swallow a narrow deny. This is the ordering
    property the whole design rests on, and it is the one thing a future
    refactor could quietly break by checking allow first.
    """
    spec2 = load(RAILS)
    # Widen the python rail to cover everything, then check that a denied
    # command inside that space still loses.
    for r in spec2.rails:
        if r.name == "python-test-suite":
            r.patterns.append(Pattern.compile("rm:*"))
    d = spec2.checker().check(["rm", "-rf", "/home/x"])
    assert d.verdict is Verdict.DENY, d


def test_unlisted_is_not_allow(spec):
    assert spec.checker().check(["made-up-tool", "--go"]).verdict is Verdict.ASK


def test_every_deny_rail_explains_itself(spec):
    """An unexplained refusal reads like a bug, and people route around bugs."""
    for rail in spec.checker().by_verdict(Verdict.DENY):
        assert rail.why.strip(), f"rail {rail.name} denies with no reason given"


def test_operator_constraints_are_present(spec):
    """
    The two commitments the rails file was written to enforce. If this fails,
    the file has been edited in a way that quietly dropped a commitment.
    """
    names = set(spec.checker().rail_names())
    assert "no-github-deletion" in names
    assert "no-force-push" in names
    irreversible = {r.name for r in spec.checker().refusals()}
    assert {"no-github-deletion", "no-force-push"} <= irreversible


def test_pattern_compile_shapes():
    p = Pattern.compile("git push:*")
    assert p.program == "git push" and p.arg_glob == "*"
    p2 = Pattern.compile(".venv/bin/python*")
    assert p2.program is None, "a path is not a bare program name"


def test_empty_argv_denied(spec):
    assert spec.checker().check([]).verdict is Verdict.DENY


# -- spec validation -------------------------------------------------------

def test_malformed_specs_are_rejected(tmp_path):
    def write(body: str) -> Path:
        p = tmp_path / "r.yaml"
        p.write_text(body)
        return p

    with pytest.raises(SpecError, match="needs at least one pattern"):
        load(write("name: x\nrails:\n  - name: a\n    kind: allow\n"))

    with pytest.raises(SpecError, match="must say why"):
        load(write("name: x\nrails:\n  - name: a\n    kind: deny\n"
                   "    patterns: ['rm:*']\n"))

    with pytest.raises(SpecError, match="duplicate rail"):
        load(write("name: x\nrails:\n  - name: a\n    kind: allow\n"
                   "    patterns: ['ls:*']\n"
                   "  - name: a\n    kind: allow\n    patterns: ['cat:*']\n"))

    with pytest.raises(SpecError, match="allow\\|ask\\|deny"):
        load(write("name: x\nrails:\n  - name: a\n    kind: maybe\n"
                   "    patterns: ['ls:*']\n"))


def test_context_is_not_a_rail(spec):
    """
    Context is prose for a judge. If it ever became enforceable, the file
    would be claiming an enforcement that does not exist.
    """
    assert spec.context, "the example should carry project context"
    assert all(r.name not in spec.context for r in spec.rails)
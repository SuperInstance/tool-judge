"""
The advisory flags; it must never refuse, because the moment it does it
becomes a policy engine and policy engines with opinions get bypassed.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tool_judge.advisory import Flag, review          # noqa: E402
from tool_judge.decisionlog import DecisionLog, REASONS  # noqa: E402
from tool_judge.harness import UnverifiedAdapter, registry, verified  # noqa: E402
from tool_judge.spec import load                       # noqa: E402

RAILS = ROOT / "rails" / "g1-ble-backend.yaml"


def test_wide_scope_with_thin_reason_is_flagged():
    f = review("kubectl:*", "user", "need kubectl")
    assert any(x.severity == "refuse-recommendation" for x in f), f


def test_narrow_scope_with_thin_reason_is_not_flagged_for_scope():
    f = review("kubectl:*", "task", "need kubectl")
    assert not any("too wide" in x.title for x in f)


def test_wide_scope_with_a_real_reason_passes():
    long_why = ("I need to poll the staging cluster for the rest of this "
                "deployment because the operator will not be present.")
    f = review("kubectl:*", "user", long_why)
    # Only the scope flag is under test here. `kubectl:*` is *also* a broad
    # pattern and is legitimately flagged for that separate reason.
    assert not any("too wide" in x.title for x in f), f


def test_collides_with_a_rail_is_flagged():
    f = review("sudo:*", "task", "install a build dependency locally", rails=load(RAILS))
    assert any("rail" in x.title for x in f), f


def test_bare_star_pattern_is_flagged():
    assert any("matches everything" in x.title
               for x in review("rm:*", "task", "cleanup between runs"))


def test_no_justification_is_noted_but_never_blocks():
    f = review("ls:*", "task", "")
    assert any("no justification" in x.title for x in f)


def test_review_returns_flags_not_a_verdict():
    """Structural: nothing here can return 'deny'."""
    for args in (("rm:*", "task", "x"), ("sudo:*", "user", ""), ("ls:*", "user", "y")):
        out = review(*args)
        assert all(isinstance(x, Flag) for x in out)


def test_unverified_harness_refuses_to_write():
    a = registry()["claude-code"]
    assert not a.verified
    try:
        a.apply([], )
    except UnverifiedAdapter as exc:
        assert "refusing" in str(exc)
    else:
        raise AssertionError("an unverified adapter must not write")


def test_verified_harness_is_mcode():
    assert verified() == ["mcode"]


def test_decision_log_renders_a_readable_sentence(tmp_path):
    log = DecisionLog(tmp_path / "d.log")
    log.record("allow", scope="task:t7", pattern="kubectl:*",
               reason="inspecting the staging cluster", decided_by="casey")
    text = log.path.read_text()
    assert "inspecting the staging cluster" in text
    assert "casey" in text


def test_decision_log_rejects_nonsense_verdicts(tmp_path):
    log = DecisionLog(tmp_path / "d.log")
    try:
        log.record("probably_fine")
    except ValueError:
        pass
    else:
        raise AssertionError("a free-text verdict would defeat the point")


def test_decision_log_summary_counts(tmp_path):
    log = DecisionLog(tmp_path / "d.log")
    log.record("allow", reason=REASONS["allow_by_grant"])
    log.record("deny", reason=REASONS["deny_by_rail"])
    assert "2 decisions" in log.summary()


# -- harness adapter: verify after write -----------------------------------

def test_adapter_verifies_what_it_wrote(tmp_path, monkeypatch):
    """
    Writing without reading back is how a permission file ends up valid JSON
    that the harness ignores. The adapter must prove its own write.
    """
    import json as _json
    from tool_judge.harness import Adapter
    from tool_judge.rails import Rail, Verdict

    target = tmp_path / "perm.json"
    rail = Rail(name="r", kind=Verdict.ALLOW,
                patterns=[__import__("tool_judge.rails", fromlist=["Pattern"])
                          .Pattern.compile("ls:*")])
    a = Adapter(name="fake", path=target, verified=True, notes="test",
                build=lambda p: {"tool_name": "bash",
                                 "matcher": {"kind": "command", "pattern": p}},
                lists={"allow": "allow", "ask": "ask", "deny": "deny"})

    res = a.apply([rail])
    assert res.verified, res.problems
    doc = _json.loads(target.read_text())
    assert any(r["matcher"]["pattern"] == "ls:*" for r in doc["allow"])


def test_adapter_is_idempotent(tmp_path):
    import json as _json
    from tool_judge.harness import Adapter
    from tool_judge.rails import Pattern, Rail, Verdict

    target = tmp_path / "perm.json"
    rail = Rail(name="r", kind=Verdict.ALLOW, patterns=[Pattern.compile("ls:*")])
    a = Adapter(name="fake", path=target, verified=True, notes="t",
                build=lambda p: {"tool_name": "bash",
                                 "matcher": {"kind": "command", "pattern": p}},
                lists={"allow": "allow"})
    a.apply([rail])
    again = a.apply([rail])
    doc = _json.loads(target.read_text())
    assert len([r for r in doc["allow"]
                if r["matcher"]["pattern"] == "ls:*"]) == 1
    n_added = sum(len(v) for v in again.added.values())
    assert n_added == 0, "re-applying duplicated a rule"


def test_adapter_refuses_to_clobber_invalid_json(tmp_path):
    from tool_judge.harness import Adapter
    from tool_judge.rails import Pattern, Rail, Verdict

    target = tmp_path / "perm.json"
    target.write_text("{not json")
    a = Adapter(name="fake", path=target, verified=True, notes="t",
                build=lambda p: {"pattern": p},
                lists={"allow": "allow"})
    rail = Rail(name="r", kind=Verdict.ALLOW, patterns=[Pattern.compile("ls:*")])
    try:
        a.apply([rail])
    except RuntimeError as exc:
        assert "not valid JSON" in str(exc)
    else:
        raise AssertionError("must not overwrite a file it could not parse")

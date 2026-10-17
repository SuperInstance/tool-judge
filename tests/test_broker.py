"""
The broker: an agent may REQUEST, a human may GRANT.

If this file is deleted the tool stops being a permission layer and becomes a
suggestion engine, because an agent that can widen its own scope will widen
it. So these tests are mostly about absence -- about what the agent-facing
surface does NOT expose -- and about the one path that does write.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tool_judge.grants import GrantStore       # noqa: E402
from tool_judge.mcp_server import TOOLS, Server  # noqa: E402

RAILS = str(ROOT / "rails" / "g1-ble-backend.yaml")


@pytest.fixture
def server():
    with tempfile.TemporaryDirectory() as tmp:
        st = GrantStore(Path(tmp) / "b.db")
        yield Server(st, RAILS)
        st.close()


# -- the structural property ----------------------------------------------

def test_agent_surface_has_no_granting_tool():
    """
    The load-bearing test. Enumerated from the actual TOOLS table, so adding
    a tool that can write a grant fails here loudly rather than shipping.
    """
    names = {t["name"] for t in TOOLS}
    forbidden = {"grant", "decide", "approve", "set_grant", "revoke",
                 "set_permission", "add_grant"}
    assert not (names & forbidden), f"agent can grant itself: {names & forbidden}"


def test_every_exposed_tool_is_dispatchable():
    """A tool advertised but not wired is exactly the defect class this repo
    has now been bitten by four times. Check the table against the server."""
    for tool in TOOLS:
        assert hasattr(Server, f"t_{tool['name']}"), \
            f"{tool['name']} is advertised but Server has no t_{tool['name']}"


# -- request does not grant ------------------------------------------------

def test_request_does_not_grant(server):
    r = server.t_request_grant({
        "pattern": "git commit:*", "scope": "task", "key": "t1",
        "justification": "recording a measurement"})
    assert r["granted"] is False
    assert r["status"] == "pending"

    # Still not permitted until a human decides.
    chk = server.t_check_command({"argv": ["git", "push", "origin", "main"],
                                  "task": "t1"})
    assert chk["verdict"] in ("ask", "deny")


def test_human_approval_makes_it_real(server):
    rid = server.t_request_grant({
        "pattern": "kubectl:*", "scope": "task", "key": "t1",
        "justification": "checking the test cluster"}).get("request_id")

    before = server.t_check_command({"argv": ["kubectl", "get", "pods"],
                                    "task": "t1"})
    assert before["verdict"] == "ask", "granted before anyone approved it"

    out = server.store.decide(rid, True, by="casey")
    assert out["status"] == "approved"

    after = server.t_check_command({"argv": ["kubectl", "get", "pods"],
                                    "task": "t1"})
    assert after["verdict"] == "allow"
    assert after["decided_by"] and after["decided_by"].startswith("grant")


def test_refusal_grants_nothing(server):
    rid = server.t_request_grant({
        "pattern": "rm:*", "scope": "user", "key": "casey",
        "justification": "would be convenient"}).get("request_id")
    server.store.decide(rid, False, by="casey")
    assert server.t_check_command({"argv": ["rm", "-rf", "x"],
                                   "user": "x"})["verdict"] != "allow"


def test_a_request_cannot_be_decided_twice(server):
    rid = server.t_request_grant({
        "pattern": "ls:*", "scope": "task", "key": "t1",
        "justification": "x"}).get("request_id")
    server.store.decide(rid, True)
    with pytest.raises(ValueError, match="already"):
        server.store.decide(rid, False)


# -- scoping still holds through the broker --------------------------------

def test_approval_does_not_travel_to_another_machine(server):
    rid = server.t_request_grant({
        "pattern": "jetson_clocks:*", "scope": "hardware", "key": "orion-01",
        "justification": "read the clock on the bench unit"}).get("request_id")
    server.store.decide(rid, True)

    assert server.t_check_command({"argv": ["jetson_clocks", "--show"],
                                   "hardware": "orion-01"})["verdict"] == "allow"
    assert server.t_check_command({"argv": ["jetson_clocks", "--show"],
                                   "hardware": "orion-02"})["verdict"] != "allow"


def test_denied_by_rails_stays_denied_after_a_grant(server):
    """An agent cannot buy its way past a rail by getting a grant approved."""
    rid = server.t_request_grant({
        "pattern": "sudo:*", "scope": "user", "key": "casey",
        "justification": "need to install a package"}).get("request_id")
    server.store.decide(rid, True)
    chk = server.t_check_command({"argv": ["sudo", "apt", "install", "x"]})
    assert chk["verdict"] == "deny", "a grant overrode a rail deny"


# -- the reason must name the deciding layer -------------------------------

def test_reason_names_the_layer_that_decided(server):
    """Reporting a verdict with an unrelated reason trains readers to ignore
    the reason. Caught once already: 'allow' accompanied by 'no grant covers
    this'."""
    by_rail = server.t_check_command({"argv": ["git", "status", "-sb"]})
    assert by_rail["verdict"] == "allow"
    assert "no applicable grant" not in by_rail["reason"], by_rail["reason"]

    denied = server.t_check_command({"argv": ["sudo", "rm", "/etc/x"]})
    assert denied["verdict"] == "deny"
    assert "rail" in (denied["decided_by"] or "") or denied["reason"]


# -- protocol --------------------------------------------------------------

def test_initialize_and_tools_list(server):
    init = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                          "params": {}})
    assert init["result"]["protocolVersion"]
    assert init["result"]["capabilities"]["tools"] == {}

    tl = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert {t["name"] for t in tl["result"]["tools"]} == {t["name"] for t in TOOLS}


def test_notification_gets_no_reply(server):
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_unknown_tool_is_an_error_not_a_crash(server):
    r = server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                       "params": {"name": "wipe_everything", "arguments": {}}})
    assert r["error"]["code"] == -32601


def test_tool_exception_is_returned_as_content(server):
    r = server.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                       "params": {"name": "check_command",
                                  "arguments": {"argv": "not-an-array"}}})
    assert "result" in r
    assert r["result"].get("isError") in (True, False)


def test_responses_are_json_serialisable(server):
    """A server that emits unserialisable output dies mid-session, silently."""
    out = server.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                         "params": {"name": "list_grants", "arguments": {}}})
    json.dumps(out)
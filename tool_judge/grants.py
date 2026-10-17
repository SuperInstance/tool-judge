"""
Grant storage, and the device profile that makes hardware scoping concrete.

SQLite because the permissions that matter most are the ones you cannot
recreate: a set that took a week to accrue on a machine you no longer have
access to. A file survives that; a model's memory does not.

Why a separate table per concern is avoided: one `grants` table with a
(scope, key) composite is enough for all six scopes, and the schema stays
small enough to read in one sitting. A safety store whose schema you cannot
hold in your head is a safety store nobody audits.

    grants     the permissions themselves, scoped
    profiles   named bundles of grants ("the safe set for an Orin")
    devices    what this machine actually is, so hardware scope is knowable
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .scope import Grant, GrantSet, Scope

SCHEMA = """
CREATE TABLE IF NOT EXISTS grants (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scope      TEXT NOT NULL,
    key        TEXT NOT NULL,
    pattern    TEXT NOT NULL,
    verdict    TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    granted_by TEXT NOT NULL DEFAULT 'human',
    created_at REAL NOT NULL,
    UNIQUE(scope, key, pattern, verdict)
);
CREATE INDEX IF NOT EXISTS grants_lookup ON grants(scope, key);

CREATE TABLE IF NOT EXISTS profiles (
    name       TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    scope      TEXT NOT NULL,
    key        TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id         TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,          -- jetson-orin, g1-arm, laptop, ...
    label      TEXT NOT NULL DEFAULT '',
    facts      TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL
);

-- Pending requests exist because the agent must NOT be able to grant itself.
-- If an agent can call grant(), the entire permission layer is theatre: it
-- simply approves whatever it wants next. So the MCP exposes request, and a
-- HUMAN clears the queue. Nothing else writes to grants.
CREATE TABLE IF NOT EXISTS pending (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scope       TEXT NOT NULL,
    key         TEXT NOT NULL,
    pattern     TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    justification TEXT NOT NULL DEFAULT '',
    requester   TEXT NOT NULL DEFAULT 'agent',
    status      TEXT NOT NULL DEFAULT 'pending',
    decided_by  TEXT NOT NULL DEFAULT '',
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


@dataclass
class Device:
    """A physical machine this permission set knows about.

    The `facts` are not decoration. A hardware-scoped grant is only
    meaningful if the machine's properties are known: the same command can be
    routine on a dev laptop and destructive on a device with one writable
    partition and no spare JTAG.
    """
    id: str
    kind: str
    label: str = ""
    facts: dict | None = None

    def fact(self, name: str, default=None):
        return (self.facts or {}).get(name, default)

    def __str__(self) -> str:
        return f"{self.id} ({self.kind}) {self.label}".strip()


class GrantStore:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # -- grants -----------------------------------------------------------

    def grant(self, scope: Scope | str, key: str, pattern: str, verdict: str,
              *, reason: str = "", granted_by: str = "human") -> Grant:
        s = Scope.parse(scope) if isinstance(scope, str) else scope
        if verdict not in ("allow", "ask", "deny"):
            raise ValueError(f"verdict must be allow|ask|deny, got {verdict!r}")
        now = time.time()
        self._conn.execute(
            "INSERT OR REPLACE INTO grants"
            " (scope,key,pattern,verdict,reason,granted_by,created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (s.label, key, pattern, verdict, reason, granted_by, now))
        self._conn.commit()
        return Grant(s, key, pattern, verdict, reason, granted_by, now)

    def revoke(self, scope: Scope | str, key: str, pattern: str) -> int:
        s = Scope.parse(scope) if isinstance(scope, str) else scope
        cur = self._conn.execute(
            "DELETE FROM grants WHERE scope=? AND key=? AND pattern=?",
            (s.label, key, pattern))
        self._conn.commit()
        return cur.rowcount

    def grants(self) -> GrantSet:
        rows = self._conn.execute(
            "SELECT * FROM grants ORDER BY created_at").fetchall()
        return GrantSet(
            Grant(scope=Scope[r["scope"].upper()], key=r["key"], pattern=r["pattern"],
                  verdict=r["verdict"], reason=r["reason"],
                  granted_by=r["granted_by"], created_at=r["created_at"])
            for r in rows)

    # -- profiles ---------------------------------------------------------

    def save_profile(self, name: str, scope: Scope | str, key: str,
                     description: str = "") -> None:
        s = Scope.parse(scope) if isinstance(scope, str) else scope
        self._conn.execute(
            "INSERT OR REPLACE INTO profiles (name,description,scope,key,created_at)"
            " VALUES (?,?,?,?,?)",
            (name, description, s.label, key, time.time()))
        self._conn.commit()

    def profile(self, name: str) -> dict | None:
        r = self._conn.execute("SELECT * FROM profiles WHERE name=?",
                               (name,)).fetchone()
        return dict(r) if r else None

    def profiles(self) -> list[dict]:
        return [dict(r) for r in
                self._conn.execute("SELECT * FROM profiles ORDER BY name")]

    def import_profile(self, name: str, *, granted_by: str = "profile-import") -> int:
        """
        Pull every grant at a profile's scope/key into this store.

        The mechanism behind "grab the safe set for that Orin": one call, and
        the set arrives attributed to where it came from so it can be traced
        back or removed wholesale.
        """
        p = self.profile(name)
        if not p:
            raise KeyError(f"no such profile: {name}")
        n = 0
        for g in self.grants().for_scope(Scope.parse(p["scope"]), p["key"]):
            self.grant(g.scope, g.key, g.pattern, g.verdict,
                       reason=g.reason or f"from profile {name}",
                       granted_by=granted_by)
            n += 1
        return n

    def grants_from(self, granted_by: str) -> GrantSet:
        rows = self._conn.execute(
            "SELECT * FROM grants WHERE granted_by=? ORDER BY created_at",
            (granted_by,)).fetchall()
        return GrantSet(
            Grant(scope=Scope[r["scope"].upper()], key=r["key"], pattern=r["pattern"],
                  verdict=r["verdict"], reason=r["reason"],
                  granted_by=r["granted_by"], created_at=r["created_at"])
            for r in rows)

    # -- devices ----------------------------------------------------------

    def register_device(self, device_id: str, kind: str, *, label: str = "",
                        facts: dict | None = None) -> Device:
        self._conn.execute(
            "INSERT OR REPLACE INTO devices (id,kind,label,facts,created_at)"
            " VALUES (?,?,?,?,?)",
            (device_id, kind, label, json.dumps(facts or {}), time.time()))
        self._conn.commit()
        return Device(device_id, kind, label, facts or {})

    def device(self, device_id: str) -> Device | None:
        r = self._conn.execute("SELECT * FROM devices WHERE id=?",
                               (device_id,)).fetchone()
        if not r:
            return None
        return Device(r["id"], r["kind"], r["label"], json.loads(r["facts"]))

    def devices(self) -> list[Device]:
        return [Device(r["id"], r["kind"], r["label"], json.loads(r["facts"]))
                for r in self._conn.execute("SELECT * FROM devices ORDER BY id")]

    def detect(self) -> Device | None:
        """
        Best-effort identification of the machine this is running on.

        Deliberately conservative: an unrecognised machine is NOT registered
        as anything. Guessing a device id would let one machine's grants
        silently apply to another, which is the exact failure hardware
        scoping exists to prevent.
        """
        d = self.device("this")
        if d:
            return d
        try:
            model = Path("/proc/device-tree/model").read_text().strip("\x00").strip()
        except OSError:
            model = ""
        kind = "jetson" if "jetson" in model.lower() else (
            "glasses-host" if Path("/sys/class/bluetooth").exists() else "unknown")
        if kind == "unknown":
            return None
        return self.register_device("this", kind, label=model or kind,
                                    facts={"model": model})

    # -- pending requests --------------------------------------------------

    # THE WHOLE POINT OF THIS TABLE. An agent that can call grant() will call
    # grant() on whatever it wants next, and the permission layer becomes
    # theatre. So the agent-facing path can only ever create a pending row; a
    # human clears it. Keeping request and approval in different places, with
    # different writers, is the property that makes the rest worth having.

    def request(self, scope: Scope | str, key: str, pattern: str,
                verdict: str = "allow", *, justification: str = "",
                requester: str = "agent") -> int:
        s = Scope.parse(scope) if isinstance(scope, str) else scope
        if verdict not in ("allow", "ask", "deny"):
            raise ValueError(f"verdict must be allow|ask|deny, got {verdict!r}")
        cur = self._conn.execute(
            "INSERT INTO pending (scope,key,pattern,verdict,justification,"
            "requester,status,created_at) VALUES (?,?,?,?,?,?,'pending',?)",
            (s.label, key, pattern, verdict, justification, requester,
             time.time()))
        self._conn.commit()
        return int(cur.lastrowid)

    def pending(self, status: str = "pending") -> list[dict]:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM pending WHERE status=? ORDER BY created_at",
            (status,))]

    def decide(self, request_id: int, approve: bool, *, by: str = "human") -> dict:
        """
        Approve or refuse a pending request. THE ONLY PATH FROM REQUEST TO GRANT.

        `by` is recorded, so a later reader can tell who widened the scope --
        which is the difference between an agent bootstrapping under
        supervision and an agent that quietly did.
        """
        row = self._conn.execute("SELECT * FROM pending WHERE id=?",
                                 (request_id,)).fetchone()
        if not row:
            raise KeyError(f"no pending request {request_id}")
        if row["status"] != "pending":
            raise ValueError(f"request {request_id} already {row['status']}")

        status = "approved" if approve else "refused"
        self._conn.execute(
            "UPDATE pending SET status=?, decided_by=? WHERE id=?",
            (status, by, request_id))
        self._conn.commit()

        if approve:
            self.grant(Scope.parse(row["scope"]), row["key"], row["pattern"],
                       row["verdict"],
                       reason=row["justification"] or f"approved by {by}",
                       granted_by=by)
        return {"id": request_id, "status": status, "decided_by": by,
                "pattern": row["pattern"], "scope": row["scope"]}

    # -- meta -------------------------------------------------------------

    def set_meta(self, k: str, v: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO meta (key,value) VALUES (?,?)", (k, v))
        self._conn.commit()

    def get_meta(self, k: str, default=None):
        r = self._conn.execute("SELECT value FROM meta WHERE key=?", (k,)).fetchone()
        return r["value"] if r else default

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "GrantStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
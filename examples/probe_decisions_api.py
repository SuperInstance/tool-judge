#!/usr/bin/env python3
"""
Pin the decision-server question schema in one run.

WHY THIS EXISTS

`tool_judge/goalfit.py` knows the endpoint (`POST /v1/decisions` -- confirmed,
because it answers with structured 422s naming the offending field, where a
wrong endpoint would 404) but not the full inner schema for a question object.

That was found the slow way: the judge was pointed at Ollama's `/api/generate`,
which the decision server does not implement. Every call returned HTTP 404,
which `goalfit.py` caught -- being a gate, it fails open -- and every call came
back `fits @ 0.00`.

    Four identical confident-looking verdicts. Total outage.

That is the most dangerous shape a failure can take in a tool like this, and it
is the specific failure this tool is supposed to catch in other software. So
the schema discovery is a script rather than a guess baked into the library,
and `degraded_count` exists so that "everything degraded" can never again look
like "everything agreed".

WHAT IT DOES

Walks candidate question shapes, POSTs each, and prints the server's complaint
until one is accepted. Every rejection is verbatim, because the error messages
are the documentation.

Run:
    python examples/probe_decisions_api.py
    python examples/probe_decisions_api.py --url http://127.0.0.1:11435
"""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:11435"
MODEL = "winnow:e4b"

STATE = {
    "project_context": (
        "A bleak backend for Even Realities G1 smart glasses. Silence is the "
        "default; an unnecessary interruption is the worst outcome."
    ),
    "command": "git commit -m 'record the falsification'",
}

# Each candidate is a plausible reading of the schema, most-likely first.
# The server tells us which one is wrong and how, so this converges fast.
CANDIDATES: list[tuple[str, dict]] = [
    ("choice.criteria as list of {id,prompt,choices}", {
        "type": "choice",
        "choice": {"criteria": [{
            "id": "goal_fit",
            "prompt": "Does this command belong to this project's work?",
            "choices": ["fits", "drift", "foreign", "dangerous"],
        }]},
    }),
    ("choice.criteria as list of strings", {
        "type": "choice",
        "choice": {"criteria": [
            "Does this command belong to this project's work?",
        ]},
    }),
    ("choice.criteria as {id,prompt,choices}", {
        "type": "choice",
        "choice": {"criteria": {
            "id": "goal_fit",
            "prompt": "Does this command belong to this project's work?",
            "choices": ["fits", "drift", "foreign", "dangerous"],
        }},
    }),
    ("score.criteria as list", {
        "type": "score",
        "score": {"criteria": [{
            "id": "goal_fit",
            "prompt": "How well does this command belong to this project's work?",
        }]},
    }),
    ("noul.criteria as dict", {
        "type": "noul",
        "noul": {"criteria": {
            "id": "goal_fit",
            "prompt": "How well does this command belong to this project's work?",
        }},
    }),
]


def probe(url: str, question: dict) -> tuple[bool, str]:
    payload = {"model": MODEL, "state": STATE, "questions": {"goal_fit": question}}
    req = urllib.request.Request(
        url.rstrip("/") + "/v1/decisions",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return True, json.dumps(json.loads(r.read()), indent=2)
    except urllib.error.HTTPError as exc:
        try:
            return False, exc.read().decode()[:300]
        except Exception:                                    # noqa: BLE001
            return False, f"HTTP {exc.code}"
    except Exception as exc:                                 # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--model", default=MODEL)
    a = ap.parse_args()

    print(f"probing {a.url}/v1/decisions with model {a.model}\n")
    for label, question in CANDIDATES:
        ok, detail = probe(a.url, question)
        mark = "ACCEPTED" if ok else "rejected"
        print(f"[{mark}] {label}")
        if ok:
            print("\nSCHEMA FOUND. Paste into tool_judge/goalfit.py as QUESTION:\n")
            print(json.dumps(question, indent=2))
            print("\nand update the parser: the answer key may not be "
                  "'goal_fit'. Inspect the response above for the actual shape.")
            return 0
        print(f"    {detail}\n")
    print("none accepted -- the schema needs a human with the server source")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
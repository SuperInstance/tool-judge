# LIMITS

What this tool cannot do, written before it is used rather than after it
misbehaves.

---

## 1. It is not a security boundary against a capable agent

The allow set includes `python3:*` and `.venv/bin/python*`. Either can
`shutil.rmtree` a working tree. So a deny rule for `gh repo delete` does not
stop an agent from reaching the same outcome through an interpreter.

This is not a bug in the design; it is what an allowlist is. An allowlist
reduces how often a human is interrupted. It does not constrain intent.

**If you want a real guarantee, put it in the credential layer.** A GitHub
token without delete scope, a filesystem permission, a container. Those
enforce. A JSON file full of globs advises.

Concretely, on the box this was built on: `gh auth status` reports scopes
`gist, read:org, repo, workflow`. `repo` includes repository deletion. Until
that is scoped down, "never delete from GitHub" is a promise, not a control.

## 2. It is not sandboxing

It answers a question about a command. It does not contain a process, mediate
syscalls, or limit what a running command does with the permissions it already
has. Every command that reaches execution runs with the full authority of the
user.

## 3. The goal-fit judge is weak, and measured so

Measured against `winnow:e4b` on the example rails file:

| command | score | band |
|---|---|---|
| `git commit -m "record falsification"` | 0.58 | uncertain |
| `python3 -m pytest` | 0.52 | uncertain |

Two unambiguously in-scope commands, both scoring near the middle of the
range. At n=5 the discrimination is not demonstrated and the honest reading is
that **the judge as configured does not separate well.** The bands are coarse
on purpose, but coarse bands over an undifferentiated score is a rounding
error, not a design.

It is worth keeping because a wide separation may exist on a corpus this has
not seen, and because `degraded_count` makes outages visible. It is **not**
worth trusting as a filter until `examples/` grows an eval set with a scored
discrimination number — the same way `cycle-judge` keeps `EVAL.md`.

## 4. Unlisted is ASK, not ALLOW

An empty allowlist is not permission to do everything. It is permission to do
nothing that has not been decided. If you want a permissive tool, that is a
`kind: allow` rail you write deliberately, where it is visible.

## 5. Precedence costs you local overrides

Deny at any scope beats allow at every scope. That is deliberate — a project
folder must not be able to re-enable what you denied — but it means there is
no `tool-judge grant --force`. To un-deny, edit the wider scope. If you want
per-project exceptions to a deny, the deny is in the wrong place.

## 6. Grant storage is not tamper-evident

SQLite, writable by the same user the permissions protect. An agent with file
write can edit the grant database as easily as it can edit the rails file.

Both are *declarations you maintain*, not defences against an adversary. If
you need the second thing, you need it in the filesystem or the credential
layer.

## 7. Scope keys are strings, and nothing validates them

`hardware:orion-01` is a convention. If a caller passes `orion-1` where the
grant says `orion-01`, the grant silently does not apply and the command falls
through to ASK. That fails safe, and it is still a footgun — it looks like the
grant is there and is not firing for a reason nobody can see.

During development this exact confusion cost a failing test that looked like a
resolver bug. Treat mismatched scope keys as a bug in the caller, and check
`tool-judge list` before assuming a grant is active.

## 8. Nothing here has seen an adversarial agent

The rails encode what a thoughtful operator would write down. They have not
been tested against one that is trying to get around them, because there isn't
one here to test against. Treat the corpus in `tests/test_rails.py` as the
obvious cases, not the hard ones.
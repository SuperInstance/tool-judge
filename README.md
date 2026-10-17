# tool-judge

A permission layer that knows what your project is.

Most permission systems are a list of command strings. That list does not know
what any of them were *for*, does not know which project it belongs to, and
certainly does not know it was approved for a laptop and not for a shared
Jetson. So it either nags you forever or you hand it the whole machine.

This one takes a written statement of a project — its rails, its hardware, its
commitments — and derives permissions from it, at whatever scope fits.

```
$ tool-judge --rails .tool-judge.yaml --hardware orion-01 check jetson_clocks --show
  ALLOW  jetson_clocks --show
    from  grants: allow (hardware:orion-01)
           bench unit, ours

$ tool-judge --rails .tool-judge.yaml --hardware orion-02 check jetson_clocks --show
  ASK    jetson_clocks --show
    from  grants: unlisted
```

Same grant, different machine, no longer applies. That is the whole idea.

---

## The one distinction

Two layers that must never be confused:

| | enforces? | needs a model? | can be wrong? |
|---|---|---|---|
| **rails** | **yes** | no | no |
| **goal-fit** | no | yes | yes |

`rails.py` is a wall. `goalfit.py` is a label on the door.

An agent that asks a language model whether it may run `rm -rf` has built a
suggestion box where it needed a wall. If you only remember one thing from
this README: **the model layer cannot make a thing safe.** It can only tell you
a command is off-goal, which is a different and much smaller claim.

The posture rule, inherited from [`cycle-judge`](https://github.com/SuperInstance/cycle-judge):

- a **rail** is a verdict about the world → **fails closed**
- **goal-fit** is a gate about traffic → **fails open**

If the decision server is down, work continues. It just loses the annotation.

---

## Scopes

Permissions nest, narrowest to widest:

| scope | key | dies with |
|---|---|---|
| `task` | `t1` | this piece of work |
| `session` | `s1` | this working session |
| `project` | `/work/glasses` | the directory |
| `hardware` | `orion-01` | **the physical machine** |
| `developer` | `casey` | — |
| `user` | `casey` | — |

```bash
tool-judge grant task:t1          'curl:*'        allow   # just this task
tool-judge grant project:$PWD     'pytest:*'      allow   # this repo, any task
tool-judge grant hardware:orion-01 'jetson_clocks:*' allow # this board only
tool-judge grant user:$USER       'sudo:*'        deny    # nowhere, ever
```

### Precedence: deny is a floor

**DENY at any applicable scope wins. Then narrowest-to-widest for the rest.**

This is deliberately not plain narrowest-wins. Plain narrowest-wins means
opening a project folder could re-enable something you denied globally, and
"I opened a directory and lost my safety rails" is not an acceptable failure
mode.

The cost is honest: you cannot locally re-enable a denied command. To un-deny,
edit the wider scope. That is the intent.

Across the two layers:

```
deny   wins from either layer
allow  a scoped grant may authorise what the rails never mention
ask    the rails' answer when no grant covers it
```

Rails are the floor, not the ceiling.

---

## Device profiles

The hardware scope is the reason this exists. A command that is routine on a
dev laptop can brick a board with one writable partition and no spare JTAG,
and an allowlist cannot know the difference. So a device carries facts, and a
named bundle of grants can be handed to it.

```bash
tool-judge device add orion-01 --kind jetson-orin --label "bench unit"
tool-judge grant hardware:orion-01 'jetson_clocks:*' allow
tool-judge grant hardware:orion-01 'flash:*'         deny --reason "bricks the unit"

# on another machine, pull that box's safe set
tool-judge profile import orin-safe
```

Permissions accumulated against a machine you no longer reach are the ones you
least want to recreate. They live in SQLite for the same reason.

---

## Quick start

```bash
git clone <this repo> && cd tool-judge
pip install pyyaml

cp rails/g1-ble-backend.yaml ./.tool-judge.yaml   # edit this: it is your project
tool-judge list
tool-judge check kubectl delete namespace prod
```

Compile the rails into whatever your agent already enforces, so refusals
happen in the harness rather than in the agent's judgement:

```bash
tool-judge compile --target mcode     # dry run
tool-judge compile --target mcode --apply
```

---

## What it cannot do

Read [LIMITS.md](LIMITS.md). The short version:

1. **It is not a security boundary against a capable agent.** The allow set
   includes interpreters. A rule saying "never delete from GitHub" does not
   stop an agent reaching the same outcome through Python. For a *real*
   guarantee, scope the credential.
2. **It is not sandboxing.** It answers a question; it does not contain a
   process.
3. **The goal-fit judge is weak.** Measured, not assumed — see RESULTS.
4. **Unlisted means ASK, not ALLOW.** An empty allowlist is not permission to
   do everything. It is permission to do nothing that has not been decided.

---

## Bugs this repo found in itself

Every one of these was a *thing that looked wired and was not*, which is the
exact defect class the tool exists to catch. It caught several in itself,
which is either reassuring or humbling.

| bug | effect |
|---|---|
| `Pattern.matches` compared `argv[0] == "git push"` | **24 of ~40 rails matched nothing.** Every git command fell through to ASK. |
| judge pointed at Ollama's `/api/generate` | decision server 404s → every call degraded to `fits @ 0.00` |
| `Scope(r["scope"])` | enum looked up by *value* not *name* — every stored grant failed to load |
| allow/ask precedence in the CLI | a scoped `allow` was overridden by the rails' unlisted-default, so granting anything not already in the rails file was impossible |

The first one is the instructive one. Nothing raised. Every git command simply
asked for permission, always, forever — which looks exactly like a cautious
tool. The corpus test found it in one run.

---

## Layout

```
tool_judge/
  rails.py     deterministic enforcement. no model.
  goalfit.py   the advisory judge. fails open, counts degradations.
  scope.py     Scope, Grant, GrantSet, resolution + precedence.
  grants.py    SQLite storage, profiles, devices.
  compile.py   rails -> host-native permission rules (merge-only).
  spec.py      rails-file loading and validation.
  cli.py       the command line.
rails/         example rails files; g1-ble-backend.yaml is a real one.
tests/         61 tests. The corpus in test_rails.py is the interesting part.
examples/      probe_decisions_api.py — pins the decision-server schema.
```

## Tests

```bash
pytest -q          # 61 tests, no network, no model
```

The rails tests are a table of commands and the verdict each **must** get.
Adding a command is one line; missing a verdict is a red test.
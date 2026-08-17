# env-guard

The first shipped piece of LoopsVault, and the only one that works without a daemon.

It replaces the global `PreToolUse` hook at `~/.claude/scripts/block-env-access.sh`. The repo copy
here is the source of truth; the installed copy is a build artifact.

```
bash tools/env-guard/install.sh     # tests, backs up, installs, re-tests, rolls back on failure
bash tools/env-guard/test-guard.sh  # 95 assertions, both directions
```

## The line it draws

The old guard denied any Bash command containing the literal string `.env`. That blocked
`find . -name ".env*"`, which lists paths and reveals no value, while the `Glob` tool sat in the
same hook matcher with no rule at all and returned exactly the same paths. The line was drawn
around the filename, and the filename is not the secret.

The line here is the `=` sign:

| Side | Example | Verdict |
|---|---|---|
| Which files exist | `find . -name ".env*"`, `ls -la .env*` | allowed |
| How many variables | `wc -l .env`, `env-keys.sh --count` | allowed |
| Which variables | `env-keys.sh .env` | allowed |
| How long a value is | `env-keys.sh --shape .env` | allowed |
| **The value** | `cat .env`, `grep KEY .env`, `source .env` | **denied** |

Everything left of the `=` is inventory an agent needs to be useful. Everything right of it is the
secret. This is the same boundary the daemon will enforce later with a kernel behind it; the hook
is the version that works today, with policy behind it instead.

## How it decides

It is an **allowlist**, not a blocklist. When a command touches an env path, the verb must be one
that provably cannot open the file. An unrecognised verb is denied, so a new way to print a file is
denied by default rather than discovered in an incident.

Position matters, in two directions:

```
cat .env | head                 DENY   the dangerous verb HOLDS the env file
find . -name ".env*" | head     ALLOW  head is trimming a list of paths
find . -name ".env*" | xargs cat DENY  xargs opens the paths it receives
ls .env* && cat README.md       ALLOW  different statement, unrelated file
```

A stage that *names* an env path must use a path-inspection verb. A stage *downstream* of one that
named an env path is receiving those paths on stdin, so it may only use a verb that treats them as
text. Downstream-ness resets at each statement boundary, otherwise an unrelated later command gets
denied and the over-blocking returns in a new costume.

Separately: `ls > .env` is denied by a redirect check rather than the verb list, because `ls` is a
legitimate discovery verb and the damage is done by the `>`.

## Every denial names the next step

An agent told "blocked" writes workaround scripts. That is the behaviour that started this project.
Every denial here prints the six commands that *do* work, including the exact `env-keys.sh`
invocation for the file it just refused.

## env-keys.sh

The sanctioned capability the denials point at. Prints variable **names**, never values.

```
env-keys.sh <path>            names, one per line
env-keys.sh --shape <path>    NAME  len=44  class=token
env-keys.sh --count <path>    24
```

`--shape` reports length and character class so an agent can sanity-check a credential's plausible
shape. It never emits a character of the value, not even a prefix, because a prefix is still part of
the secret. There is no flag that prints a value; adding one would defeat the point.

## Known gap, deliberately left open

This guard has never covered `printenv`, `env`, or `echo $SOME_KEY`, because none of those contain
the string `.env`. The gap is real and predates this change. It is **not** closed here, because this
change was scoped to widen discovery without altering what is denied, and blocking bare `env` would
break a lot of legitimate commands across every project at once. Tracked in
`founder/task-guard-covers-process-env.md`.

---
title: Make block-env-access.sh allow discovery and name the next step
status: pending
category: task
created: 2026-08-17
related: [../HANDOFF.md, task-inventory-and-classify.md]
---

# Fix the env guard so it stops causing workaround loops

**Ten minutes. No dependencies. Worth doing regardless of how the three open decisions land**,
because it removes daily friction immediately and costs nothing.

## The problem, measured

`~/.claude/scripts/block-env-access.sh` is wired as a global `PreToolUse` hook in
`~/.claude/settings.json` for `Read|Edit|Write|NotebookEdit|Bash|Grep|Glob`.

For Bash, it denies **any command containing the literal string `.env`**. During the 2026-08-17
session this blocked:

```
find . -maxdepth 3 -name ".env*" -type f
```

That command lists file paths and reveals **zero** secret content. The guard cannot distinguish
discovery from disclosure.

Its denial messages also dead-end. The Bash one reads:

> "Bash commands referencing .env files are blocked globally. .env.example is allowed; cat/source/grep on other .env files is not."

An agent told "blocked" with no alternative starts writing workaround scripts. That is the exact
behaviour the founder described as the reason LoopsVault should exist.

## What to change

1. **Allow pure discovery.** Listing paths, counting files, and counting variables reveal nothing.
   Distinguish these from value reads (`cat`, `source`, `grep` for values, `printenv`).
2. **Make every denial name the next step.** Point at the catalog command. Once LoopsVault exists
   that is `loopsvault describe <NAME>` or `loopsvault ls`. Before it exists, point at
   `.env.example` and at asking the founder.
3. **Keep the value-read block exactly as strict as it is now.** This task widens discovery only.
   It must not widen disclosure.

## Pass criteria

- `find` / `ls` style discovery on env paths succeeds.
- `cat`, `source`, `grep <value>`, `printenv` on a real env file are still denied.
- Every denial message names a specific command the agent should run instead.
- Verify the **pass case**, not just the block case. Per the founder's standing rule, a guard is
  not shipped until the thing it is supposed to allow has been proven to actually work.

---

## Done 2026-08-17, awaiting founder verification

Built in `tools/env-guard/`, installed to `~/.claude/scripts/`. The hook wiring in
`~/.claude/settings.json` was NOT touched: it already pointed at that path. The previous guard was
backed up to `~/.claude/scripts/block-env-access.sh.bak-20260817-134715`.

**The line moved from the filename to the `=` sign.** Left of it (which files exist, which
variables, how many, how long a value is) is inventory an agent needs. Right of it is the secret.

- `bash tools/env-guard/test-guard.sh` - 95 assertions, both directions, all green.
- Live end-to-end: `find /Users/jain.jagi/Projects -maxdepth 3 -name ".env*" -type f` now runs
  through the real hook and returned 70 files. That is the exact command that was blocked during
  the design session.
- New capability `env-keys.sh` prints variable NAMES and never values, in three modes (names,
  `--shape` for length plus character class, `--count`). Every denial message names it, with the
  path already filled in.
- Value reads stayed exactly as strict. 18 adversarial bypasses were tried and all denied,
  including `echo $(cat .env)`, backticks, `bash -c`, `find -exec cat`, `xargs cat`,
  `while read f; do cat $f; done`, `\cat`, `CAT=cat; $CAT .env`, and interpreter one-liners.
- One thing got **stricter**, and it was not in the original scope: `ls > .env` was previously
  allowed and would truncate an env file. Now denied by a redirect check. Flagging it because it
  is the one behaviour change in the deny direction.

**Verify by running these two yourself:**

```
find ~/Projects -maxdepth 2 -name ".env*" -type f     # should list files
cat ~/Projects/pitchplus_fast/.env                    # should deny, and name env-keys.sh
```

Left at `pending`. Only the founder flips a task to `finished`.

**Found and deliberately not fixed:** the guard has never covered `printenv` / `echo $VAR` / `env`,
because those contain no `.env` string. Closing that changes what is denied, which this task was not
allowed to do. Recorded as [task-guard-covers-process-env.md](task-guard-covers-process-env.md)
with a recommendation.

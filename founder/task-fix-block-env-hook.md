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

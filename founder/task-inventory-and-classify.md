---
title: Inventory every env variable across all projects and classify it
status: pending
category: task
created: 2026-08-17
related: [../HANDOFF.md, task-fix-block-env-hook.md]
---

# Inventory and classify

**Step one of the real build.** The catalog is the feature that makes LoopsVault worth building,
and this task produces its first contents. It also sizes the whole project, which is why it comes
before any daemon code.

## Why it is not done yet

It was attempted during the 2026-08-17 design session and **blocked by the env guard**. The block
was not circumvented, deliberately: working around a security control the founder installed on
purpose is not something an agent should do quietly. See
[`task-fix-block-env-hook.md`](task-fix-block-env-hook.md), which unblocks this.

## What to collect

For every `.env`-family file under `/Users/jain.jagi/Projects/` (roughly 40 directories, around 10
actively worked):

| Field | Notes |
|---|---|
| Variable name | Names only. **Never collect values.** |
| Project | Which directory it appeared in |
| Provider | Inferred from the name where possible |
| Classification | `secret` or `decided-constant` |
| Shared? | How many projects use the same name |

## The classification rule

From the founder's global `CLAUDE.md`, "A Value Is Not An Environment Variable Until It Has To Be."
A value earns a slot in the vault only if:

1. **It is a secret.** A credential, key, token, password, or pepper.
2. **It genuinely differs between deployments that exist today.** Not "might differ one day."

Everything else is a **decided constant** and belongs in a constants module in source, not in a
vault and not in an env file.

**Expect a large reduction.** The founder's own measured precedent (findmyhooks, 2026-08-14) went
from 46 required variables to 32, of which only **24 were real secrets**. Across ten projects with
heavy provider overlap, the true vault is plausibly 30 to 50 entries rather than several hundred.

## How to run it safely

Write a script that emits **names and paths only**, never values. Then either:

- The founder runs it and pastes the output (crosses no boundary, no value access at any point), or
- The guard is adjusted first via `task-fix-block-env-hook.md` so names-only discovery is permitted,
  and the agent runs it directly.

Do not read values in either case. The catalog never needs them.

## Pass criteria

- A single table covering every project, every variable name, and its classification.
- The set of genuinely shared credentials identified (these are the ones the vault exists for).
- A count of how many entries the vault will actually hold.
- Zero secret values recorded anywhere in the output, in a scratch file, or in the transcript.

# Tasks

One-line index of every `task-*.md` in this directory, grouped by status.
Full detail lives in each linked file.

Agents never set a task to `finished`. Everything below sits in `pending` until you say otherwise,
so "pending" here means either **needs you** or **done, awaiting your verification**. The two are
marked.

## Not Working (fix these first)
<!-- (none) -->

## Needs you

- [task-service-account.md](task-service-account.md) — **The one part of v1's security story that is
  designed but not installed.** Until `_vaultd` exists, the store is protected by encryption at rest
  and by convention, not by the kernel, which means an agent running as you is stopped by nothing but
  the master key living in a file it has no reason to open. Needs sudo. Steps 4 and 5 are mine and I
  can do them the moment the account exists.

- [task-inventory-findings.md](task-inventory-findings.md) — **Three calls the inventory surfaced.**
  One is a security question and costs a minute: `CLAUDE_API_KEY_OLD` is sitting in a live env file.
  The others are the 133 ambiguous names needing your pass, and whether to normalise
  `ANTHROPIC_API_KEY` vs `CLAUDE_API_KEY` rather than carry aliases forever.

- [task-guard-data-vs-path.md](task-guard-data-vs-path.md) — **The guard cannot tell a data
  argument from a path.** Found by the jainyagi.com session, reproduced in three sessions across two
  projects, verified here. It denies commands that cannot disclose anything, and when the string
  arrives inside quoted JSON it blames a verb that never ran. Two options in the file; the safe half
  is ready to build on your word. Global config, so it waits for you.

- [task-guard-covers-process-env.md](task-guard-covers-process-env.md) — The env guard covers files
  but has never covered `printenv`, `echo $VAR`, or bare `env`, because none of those contain the
  string the guard triggers on. Closing it changes what is **denied**, so it is a decision rather
  than a fix. Recommendation is in the file.

## Done, awaiting your verification

- [task-three-open-decisions.md](task-three-open-decisions.md) — All three answered 2026-08-17.
  Endpoint-first for interception, native Rust for the proxy, CLI first for v1. Answers and their
  consequences are in the file; HANDOFF.md §11 carries the summary table.

- [task-fix-block-env-hook.md](task-fix-block-env-hook.md) — **Done 2026-08-17.** The guard's line
  moved from the filename to the `=` sign, installed globally, 100 assertions green both directions.
  Verify with the two commands at the bottom of the task file: discovery should list files, a value
  read should still be denied and should name the alternative.

- [task-inventory-and-classify.md](task-inventory-and-classify.md) — **Done 2026-08-17.** Fixing the
  guard first made it self-serve, so it needed no founder participation after all. 28 projects, 72
  env files, 429 distinct names, 100 of them real secrets. Report regenerates into `catalog/`, which
  is gitignored because the remote is public.

## Finished
<!-- founder-only transition; nothing here yet -->

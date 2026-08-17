# Tasks

One-line index of every `task-*.md` in this directory, grouped by status.
Full detail lives in each linked file.

## Not Working (fix these first)
<!-- (none) -->

## Pending

- [task-service-account.md](task-service-account.md) — **The one part of v1's security story that is
  designed but not installed.** Until `_vaultd` exists, the store is protected by encryption at rest
  and by convention, not by the kernel, which means an agent running as you is stopped by nothing but
  the master key living in a file it has no reason to open. Needs sudo, so it needs you. Steps 4 and
  5 are mine and I can do them the moment the account exists.

- [task-three-open-decisions.md](task-three-open-decisions.md) — **All three answered 2026-08-17,
  build unblocked.** Both-endpoint-first for HTTPS interception, native Rust for the proxy, CLI
  first for v1. Answers and their consequences are written into the file, and HANDOFF.md §11 now
  carries the summary table. Left `pending` because only the founder flips a task to `finished`.

- [task-fix-block-env-hook.md](task-fix-block-env-hook.md) — **Ten minutes, no dependencies, do it
  regardless of the decisions above.** `~/.claude/scripts/block-env-access.sh` denies any Bash
  command containing the literal string `.env`, so pure discovery like `find . -name ".env*"` is
  blocked alongside actual value reads, and the denial message names no alternative. That is the
  mechanical cause of agents writing workaround scripts. Allow discovery, make the denial point at
  the next step.

- [task-inventory-findings.md](task-inventory-findings.md) — **Three calls the inventory surfaced.**
  One is a security question and costs a minute: `CLAUDE_API_KEY_OLD` is sitting in a live env file.
  The others are the 133 ambiguous names needing your pass, and whether to normalise
  `ANTHROPIC_API_KEY` vs `CLAUDE_API_KEY` rather than carry aliases forever.

- [task-guard-covers-process-env.md](task-guard-covers-process-env.md) — The env guard covers files
  but has never covered `printenv` / `echo $VAR` / `env`, because those contain no `.env` string.
  Closing it changes what is denied, so it is a decision rather than a fix. Recommendation is in the
  file.

- [task-inventory-and-classify.md](task-inventory-and-classify.md) — **Step one of the real build.**
  Every variable name across all projects, which projects share which, and secret versus decided
  constant. Output is the first catalog. Needs founder participation because the guard blocks the
  survey. Expect the vault to be far smaller than it looks; the findmyhooks precedent went 46 vars
  to 24 real secrets.

## Finished
<!-- [task-foo.md](task-foo.md) — one-line hook (YYYY-MM-DD) -->

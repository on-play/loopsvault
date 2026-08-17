# Tasks

One-line index of every `task-*.md` in this directory, grouped by status.
Full detail lives in each linked file.

## Not Working (fix these first)
<!-- (none) -->

## Pending

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

- [task-inventory-and-classify.md](task-inventory-and-classify.md) — **Step one of the real build.**
  Every variable name across all projects, which projects share which, and secret versus decided
  constant. Output is the first catalog. Needs founder participation because the guard blocks the
  survey. Expect the vault to be far smaller than it looks; the findmyhooks precedent went 46 vars
  to 24 real secrets.

## Finished
<!-- [task-foo.md](task-foo.md) — one-line hook (YYYY-MM-DD) -->

# Founder's Brain — LoopsVault

This is the founder's thinking space: ideas, problems, solutions, decisions, and tasks.
See `~/.claude/CLAUDE.md` for the full category + status conventions.

**New here? Read [`../HANDOFF.md`](../HANDOFF.md) first.** It is the complete design transfer from
the 2026-08-17 session and contains everything decided, everything rejected, and the three open
decisions that block the build.

## Tasks
See [TODO.md](TODO.md) for the consolidated task list.

## Index

### Vision
<!-- vision-*.md entries -->

### Decisions

- Stack: Rust daemon + Swift/SwiftUI GUI over a Unix domain socket (2026-08-17, in HANDOFF.md §7)
- License: MIT (2026-08-17)
- Platform floor: macOS first, Apple Silicon as a product choice not a hardware limit
  (2026-08-17, in HANDOFF.md §7)
- Write-only credentials, GitHub Secrets semantics (2026-08-17, in HANDOFF.md §5)
- Out of scope: provider low-balance alerts, since OpenRouter already does this (2026-08-17)

### Solutions
<!-- solution-*.md entries -->

### Ideas
<!-- idea-*.md entries -->

### Problems
<!-- problem-*.md entries -->

### Parked / Killed

- Webcam face recognition for continuous verification. Instinct was right, mechanism was wrong.
  Redirected into Touch ID + Secure Enclave. Reasoning in HANDOFF.md §9. Do not re-propose.

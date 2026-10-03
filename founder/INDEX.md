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

- [vision-use-not-have.md](vision-use-not-have.md): the agent gets the use of a secret (API, SSH,
  database, signing), never the secret, on a laptop, a server or the live app. No sandbox needed
  (2026-10-03). Research behind it: [../research/2026-10-03-agents-and-linux.md](../research/2026-10-03-agents-and-linux.md)

### Decisions

- HTTPS interception: both, endpoint first. v1 is the explicit local endpoint only; MITM is opt-in,
  per-tool, off by default, and lands after v1 (2026-08-17, in HANDOFF.md §11)
- Proxy implementation: native Rust. Agent Vault is a reference design, not a dependency
  (2026-08-17, in HANDOFF.md §11)
- v1 scope: CLI first, GUI after. Daemon + CLI + catalog + endpoint proxy + per-project attribution.
  SwiftUI, Secure Enclave, Touch ID and honeytokens are v2 (2026-08-17, in HANDOFF.md §11)
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

# CLAUDE.md — LoopsVault

## Read HANDOFF.md before doing anything

[`HANDOFF.md`](HANDOFF.md) is the complete design transfer from the 2026-08-17 session where this
project was conceived. It contains every decision made, every alternative rejected and why, the
prior art already researched, the honest security model, and the facts verified about this machine.

**Read it in full before your first substantive action.** It exists so you do not re-research, do
not re-propose dead ideas, and do not rediscover constraints the hard way.

## Three decisions block the build

`founder/task-three-open-decisions.md` holds three architecture questions that were deliberately
left unanswered:

1. How the proxy intercepts HTTPS (explicit local endpoint vs MITM with a local CA)
2. Whether the proxy is written in Rust or wraps Infisical's Agent Vault
3. What ships in v1

Each has a recommendation. **None is decided.** Ask the founder and record the answers in that file
before writing implementation code.

Two things are safe to do regardless: `founder/task-fix-block-env-hook.md` (ten minutes, no
dependencies) and `founder/task-inventory-and-classify.md` (needs founder participation).

## What this project is

A local encrypted vault that lets AI coding agents **use** API keys without ever **seeing** them,
while giving them a plaintext catalog of what exists and what it is for. One vault, all projects,
one key per provider, with per-project cost attribution coming from the vault rather than the
provider.

- **License:** MIT. **Domain:** loopsvault.com. **Platform:** macOS first, Linux daemon from day one.
- **Stack (decided):** Rust daemon, Swift + SwiftUI GUI, Unix domain socket between them.
- **Rejected explicitly:** Node.js, JavaScript, React. Reasoning is in HANDOFF.md §7, including a
  correction to the original rationale that is worth reading before you repeat it.

## Rules specific to this repo

- **No real credential ever enters this repository.** Not in a test fixture, not in a code comment,
  not in a commit message, not in a doc example. Use obviously fake values with an obvious prefix.
- **Exact host matching, always.** Credential injection must never match a host by suffix or
  wildcard. That is the one bug class that would actually leak a key. See HANDOFF.md §5.
- **Never hand the agent ciphertext or a decryption key.** It receives a reference. Anything else
  defeats the entire design.
- **Do not oversell the security model.** The design genuinely stops secrets reaching a model
  context window and genuinely stops file reads via the kernel. It does not stop root. Say so
  plainly whenever it comes up.
- **Verify the pass case of every guard**, not just the block case. A guard that blocks correctly
  and also blocks legitimate use is the bug this whole project exists to fix.

## Everything else

The founder's global rules in `~/.claude/CLAUDE.md` apply in full: two-branch git (`develop` and
`main`), auto-commit substantive work without asking, never push, never merge a PR, no
`Co-Authored-By`, no em dashes anywhere, verify rather than assume, and never delegate testing or
browser work to a sub-agent.

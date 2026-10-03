# CLAUDE.md — LoopsVault

## The goal (set by the founder, 2026-10-03)

**Any agent, anywhere, can do the work a secret allows, and no agent can ever see the secret.**

- Every kind of secret: API keys, SSH keys, database logins, signing keys, cloud logins.
- Every agent: Claude, Codex, Grok, Cursor, Gemini, and whatever comes next.
- Every place: a laptop, a server, the live production app.
- The vault does the operation and hands back the result. The agent gets the use, never the value.
- Work never stops: rules decided in advance cover routine and autonomous use; anything else asks
  by phone or fingerprint, and a yes lasts 30 minutes.
- No dependence on any tool's sandbox. Live servers reach a separate vault machine.
- The first thing anyone installs on a new coding machine, Linux and macOS alike.

Measure every change against this. Detail: `founder/vision-use-not-have.md` and
`founder/decision-approvals-and-production.md`. Research: `research/2026-10-03-agents-and-linux.md`.

## Read HANDOFF.md before doing anything

[`HANDOFF.md`](HANDOFF.md) is the complete design transfer from the 2026-08-17 session where this
project was conceived. It contains every decision made, every alternative rejected and why, the
prior art already researched, the honest security model, and the facts verified about this machine.

**Read it in full before your first substantive action.** It exists so you do not re-research, do
not re-propose dead ideas, and do not rediscover constraints the hard way.

## The three blocking decisions are answered (2026-08-17)

1. **HTTPS interception: both, endpoint first.** v1 is the explicit local endpoint only. No CA is
   created or installed in v1. MITM comes later, opt-in, per-tool, off by default.
2. **Proxy: native Rust.** Infisical's Agent Vault is a reference design, never a dependency.
3. **v1 scope: CLI first, GUI after.** v1 is daemon + CLI + catalog + endpoint proxy + per-project
   attribution. SwiftUI, Secure Enclave, Touch ID and honeytokens are v2.

Reasoning in `founder/task-three-open-decisions.md`, summary table in HANDOFF.md §11. Three
constraints follow from these and must not be quietly undone: one injection core shared by both
transports, a pluggable master-key unwrapper from the first commit, and a break-glass export format
designed in v1 rather than v2.

Next up: `founder/task-fix-block-env-hook.md` (ten minutes, no dependencies) and
`founder/task-inventory-and-classify.md` (needs founder participation, and it is what makes
everything after it easy).

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

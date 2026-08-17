# LoopsVault

A local, encrypted vault that lets AI coding agents **use** API keys without ever **seeing** them,
while giving them a plaintext catalog of what exists and what it is for.

One vault on one machine, serving every project. One key per provider, not one key per project.
Per-project usage and cost attribution comes from the vault rather than from the provider.

- **License:** MIT
- **Platform:** macOS first, Linux daemon from day one
- **Status:** v1 works. See [What v1 is and is not](#what-v1-is-and-is-not) before relying on it.

## The problem

Ten projects, ten `.env` files, the same OpenRouter and Stripe and Resend keys copied into all of
them. Measured across this machine on 2026-08-17: **28 projects, 72 env files, 429 distinct variable
names.** `OPENROUTER_API_KEY` appears in 7 projects, `DATABASE_URL` in 15. Rotating one key means
editing many files.

The sharper problem is not theft, it is context. An agent that reads a `.env` file pulls every value
into a context window that is uploaded to a model API and stored in a transcript. **That is the
realistic threat, far more than a stolen laptop.**

And a guard that simply blocks `.env` makes it worse. An agent told "blocked" with no alternative
writes workaround scripts, burns turns, and produces nothing.

## The mechanism: use without seeing

The agent never enters the vault. There is no door on the agent's side.

```
agent                          loopsvaultd                     openrouter.ai
  │                                 │                                │
  │  POST /openrouter/v1/chat...    │                                │
  │  authorization: PLACEHOLDER     │                                │
  │  x-loopsvault-project-token     │                                │
  ├────────────────────────────────>│                                │
  │                                 │ resolve project from token     │
  │                                 │ check host is exactly allowed  │
  │                                 │ write the real credential in   │
  │                                 ├───────────────────────────────>│
  │                                 │<───────────────────────────────┤
  │<────────────────────────────────┤ parse usage, attribute to      │
  │  the answer, no credential      │ the project, log the call      │
```

The agent got what it needed. The key was never in its process memory, never in its terminal output,
never in its context window. **The agent is not blindfolded inside the room. It is in a different
room, sliding paper under the door.**

`ssh-agent` has worked this way since 1995.

## Quick start

```bash
cargo build --release

loopsvault init                      # config, master key (0600), empty store
$EDITOR ~/.loopsvault/config.json    # add catalog entries and providers
loopsvault set OPENROUTER_API_KEY    # reads stdin, never argv, never echoes
loopsvault project add pitchplus_fast   # prints a token, once
loopsvaultd &                        # listens on 127.0.0.1:14322
```

Then point the project at the vault instead of the provider:

```
OPENROUTER_BASE_URL=http://127.0.0.1:14322/openrouter/v1
```

and send the project token in `x-loopsvault-project-token`.

What agents can do freely, with no token and no privilege:

```bash
loopsvault ls                        # what exists, what it is for, is a value stored
loopsvault describe OPENROUTER_KEY   # purpose, allowed hosts, value shape, aliases
loopsvault usage                     # per-project calls, tokens, dollars
```

There is no `loopsvault get`. Once stored, this tool will not show you a value.

## What v1 is and is not

**Working and verified:**

- Credential injection with **exact** host matching. Never suffix, never wildcard.
- The plaintext catalog, which is the piece no other tool provides.
- Per-project attribution, with identity established by a token rather than a claimed name.
- Encryption at rest with [age](https://github.com/FiloSottile/age), store written `0600`.
- A break-glass export the stock `age` CLI can recover with no LoopsVault build. Tested through a
  pty against the real binary, because a recovery path that needs this software to compile is not a
  recovery path.
- Honeytokens: any touch is refused and alarmed, and they answer as absent so a tripwire does not
  announce itself.

**Not yet, and stated plainly:**

- **The `_vaultd` service account is designed but not installed.** Today the store is protected by
  encryption at rest and by convention, not by the kernel. See
  [`founder/task-service-account.md`](founder/task-service-account.md).
- The audit log is in memory, not durable.
- No spend caps, no SwiftUI app, no Touch ID, no Secure Enclave. Those are v2, and the v1 code is
  shaped so they drop in: the master key unwrapper is a trait with a file implementation today and
  an Enclave implementation later.
- The opt-in MITM transport is not built. v1 is the explicit local endpoint only, which is
  [Decision 1](HANDOFF.md#11-three-decisions-answered-2026-08-17) as settled.

**What it does not prevent, in any version: root.** If something has root on your Mac, it can read
the daemon's memory and disable whatever detector you build. No application-level design changes
that. What is controlled is that the damage is bounded and loud.

## The env guard

`tools/env-guard/` ships the piece that works with no daemon at all: a replacement for the global
`PreToolUse` hook that draws its line at the `=` sign rather than the filename. Path and name
discovery are allowed, values are not, and every denial names the next step. See
[`tools/env-guard/README.md`](tools/env-guard/README.md).

## Layout

```
crates/loopsvault-core/   catalog, exact host matching, the injection core, meter, project identity
crates/loopsvaultd/       the daemon: endpoint transport, encrypted store, HTTP surface
crates/loopsvault-cli/    the loopsvault command
tools/env-guard/          the PreToolUse hook and env-keys.sh
tools/inventory/          survey and classify env variables across every project
tools/smoke.sh            end-to-end test of the shipped binaries
```

`loopsvault-core` knows nothing about HTTP. Every "may this credential go to that host" question is
answered there, so the endpoint transport and the later MITM transport share one implementation.
**If a host comparison ever appears in a transport, that is the constraint breaking.**

## Tests

```bash
cargo test          # 68: unit, plus 8 end-to-end through the real router and store
bash tools/smoke.sh # drives the shipped binaries, starts and stops a real daemon
bash tools/env-guard/test-guard.sh   # 100 assertions, both directions
```

The end-to-end test worth reading is `the_upstream_gets_the_credential_and_the_caller_never_does`.
Everything else is detail.

## Background

[`HANDOFF.md`](HANDOFF.md) is the full design record: the decisions, the alternatives rejected and
why, the prior art already evaluated, and an honest security model.

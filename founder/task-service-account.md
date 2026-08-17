---
title: Create the _vaultd service account and the launchd plist
status: pending
category: task
created: 2026-08-17
related: [../HANDOFF.md, ../crates/loopsvault-cli/src/main.rs]
---

# The kernel boundary is not in place yet

v1 works, and this is the one piece of its security story that is designed but not installed.

## What the handoff promises

The store file is `0600` owned by `_vaultd`, a background service account. When an agent running as
`jain.jagi` tries to read it, **the refusal comes from the macOS kernel, not from LoopsVault code.**
That is the single change that converts the design from policy-enforced to kernel-enforced. Verified
on this machine on 2026-08-17: 130 service accounts already exist, and only `jain.jagi` (501) and
`budankai` (502) can log in at all.

## What v1 actually does

The daemon and the CLI both run as the founder. The store is `0600` owned by `jain.jagi`.

That still stops a **different user** on the machine. It does not stop an agent running as the
founder, which is the threat model that matters here, because that is what every Claude Code and
Codex session is.

**Be precise about what this means and what it does not.** Encryption at rest is real and already
working: a stolen laptop, a leaked backup, an iCloud sync and an accidental `git commit` are all
covered today, because the store is an age file. What is missing is the boundary that stops a
process running as you from reading the master key file and decrypting it. Right now that is
prevented by nothing except the master key living in a separate file the agent has no reason to
open, which is a convention, not a boundary.

## Why it was not done in this pass

It needs `sysadminctl` or `dscl` to create the account, `chown` on the store, and a `launchd` plist
in `/Library/LaunchDaemons`. All of that needs sudo, changes system state outside any project, and
is not reversible by `git checkout`. It is the kind of thing that should be run deliberately rather
than as a side effect of a build session.

## What needs to happen

1. Create `_vaultd` as a non-login service account with a uid in the service range.
2. `chown _vaultd` on `~/.loopsvault/vault.store` and `master.key`, mode `0600`.
3. A `launchd` plist that starts `loopsvaultd` as `_vaultd` at boot.
4. Move the CLI's admin commands (`set`, `rm`, `export`, `project`) from opening the store directly
   to talking to the daemon over a **Unix domain socket**, since after step 2 they can no longer
   read the file. The socket's own file permissions become the access control, which is the point:
   kernel-enforced rather than argued.
5. Delete the direct-open code path in `crates/loopsvault-cli/src/main.rs` so it cannot silently
   come back.

## Needed from you

Step 1 to 3 need sudo. Say the word and I will write the exact commands and the plist for you to run,
or walk them with you. Step 4 and 5 are mine and I can do them as soon as the account exists.

Until then, treat the v1 store as protected by encryption at rest and by convention, not by the
kernel.

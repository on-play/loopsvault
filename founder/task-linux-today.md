---
title: Bring LoopsVault to the Linux machine
status: pending
category: task
created: 2026-10-03
related: [vision-use-not-have.md, decision-approvals-and-production.md, ../tools/linux-probe.sh]
---

# Bring LoopsVault to the Linux machine, 2026-10-03

The agent cannot reach the Linux machine (SSH is blocked for agents by global policy), so the two
steps that need the machine itself are yours. Everything else is the agent's.

## Yours

1. **Push `main`.** 15+ commits are local only; GitHub still has the 19 August code, which is what
   the Linux machine would build. `git push origin main`
2. **On the Linux machine, run the probe and paste the whole output back:**
   ```bash
   curl -fsSL https://raw.githubusercontent.com/on-play/loopsvault/main/tools/linux-probe.sh | bash
   ```
   It prints distro, chip type, systemd version, whether there is a TPM chip, which agents are
   installed, and how Claude is set up there (rule names only). It never prints a secret value.

## The agent's, as soon as the probe output is back

- Build steps fitted to that distro and chip.
- Today, with v1 as it is: the vault running as you, keys moved in, the env guard and status line
  installed for Claude, and the same guard wired into Codex and Grok from one shared copy.
- Next: the vault under its own Linux account (systemd), so the kernel, not convention, keeps
  agents out of the store. Needs the CLI to talk to the daemon over a socket first, which is code
  the agent writes on the Mac.

## Pass / fail

- Pass: on Linux, `loopsvault ls` lists entries, a real call through `127.0.0.1:14322` succeeds,
  and `cat` of the store from an agent shows ciphertext only.
- Fail: anything that asks you to paste a key into a terminal an agent can see.

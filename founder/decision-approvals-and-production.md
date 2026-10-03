---
title: How permission is given, and where the vault runs for live servers
status: decided
category: decision
created: 2026-10-03
related: [vision-use-not-have.md, ../HANDOFF.md]
---

# Decided 2026-10-03

## First user

Solo developers running many agents (Claude, Codex, Grok, Cursor and others) across their own
laptops and servers. The founder is user one. Teams come later.

## How permission is given: all three, chosen by purpose

The founder's words: "all three: phone notification, fingerprint on the machine, rules decided in
advance. Once they give permission, it should last for 30 minutes. It should work for people who work
remotely, from a phone or a tablet, to automate things. Sometimes the agents run autonomously, so in
that case it should work. Depending on the purpose, the permission request changes."

What this means for the build:

1. **Rules decided in advance** cover routine use, so an agent running on its own at 3am keeps
   working with no one awake. Example: project `pitchplus_fast` may use `OPENROUTER_API_KEY` against
   `openrouter.ai`, always.
2. **Phone notification** for anything a rule does not already allow. Works when the founder is away
   from the laptop and when the agent runs on a server with no screen.
3. **Fingerprint on the machine** when the founder is at it, and for the highest-risk actions.
4. **An approval lasts 30 minutes** by default, then the agent has to ask again.
5. **The secret's purpose decides which of the three applies.** Each catalog entry carries its own
   approval rule, so an LLM key can be "always, by rule" while a production SSH key is "ask every
   time, phone or fingerprint".

Catalog consequence: entries gain an `approval` field (rule, phone, fingerprint, and the window).

## Where the vault runs for live servers: a separate machine

Secrets live on one machine that agents never run on. A live server runs only a small relay with no
secrets in it; it asks the vault machine to perform the operation and gets the result.

**Why this is the stronger choice:** agents on servers often run as root, and root on the machine
holding the vault can read the vault's memory. With the vault elsewhere, root on a server can at most
*use* what the rules allow, logged and revocable, and can never take a key away.

**Honest limit:** the relay proves its identity to the vault with a credential that lives on the
server, and root there can take that credential. What it gets is the same limited, logged,
revocable use, never the underlying secrets. Revoke the relay and it is over.

The laptop keeps a local vault as today. The daemon is one program in both places; on the vault
machine it also listens on the network for relays.

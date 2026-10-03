---
title: The agent gets the use of a secret, never the secret, anywhere it runs
status: decided
category: vision
created: 2026-10-03
related: [../HANDOFF.md, ../research/2026-10-03-agents-and-linux.md]
---

# The agent gets the use of a secret, never the secret

Stated by the founder on 2026-10-03, after starting to code on a new Linux machine:

> Whatever is inside LoopsVault is highly restricted, but it should not stop the work that needs to
> be done with access to that something. If it's SSH, it should not see the key, but it can use SSH
> and connect to the server. An agent can find a way to escape. But no agent should be able to
> escape the LoopsVault. Still, work can be done.

And: forget the sandbox. A sandbox belongs to one tool on one machine. LoopsVault has to hold on a
laptop, on a server, and in the live production app, for every agent.

## What this widens

HANDOFF.md §3 already said non-HTTP secrets get a capability, not a credential. This makes it the
centre of the product rather than a footnote. Every kind of secret gets a way to be used:

| Secret | How the agent uses it without holding it |
|---|---|
| API key | The vault adds it to the outgoing request (built, v1) |
| SSH key | The vault is the SSH agent: it signs the login, the key never leaves. Approval per server and time window |
| Git signing | Same SSH agent |
| Database password | The vault connects with the real password; the agent connects to the vault with none |
| Webhook / token signing key | The agent asks for a signature, gets a signature |
| Cloud login (AWS) | The vault signs the request (SigV4), the agent never holds the pair |
| Anything else | The vault runs a fixed, pre-approved command as its own user, and removes the secret from the output |

## Live servers too

On a server the app itself goes through the vault. An agent with a shell on that server finds no key
in the app's environment, because the app never had one.

## Where it honestly holds and where it does not

- **Root on the vault's machine defeats it.** Agents on servers often run as root. For production
  the real wall is that the vault lives on a different machine from where agents run; the server
  gets the use of secrets, never the secrets.
- **Using SSH can hand out access even though the key stays hidden.** Once logged in, an agent could
  add its own key to `authorized_keys`. The fix is short-lived SSH certificates issued by the vault,
  so access ends when the approval ends.
- **A response can carry a secret back.** An API that creates keys, or an error page that echoes the
  header. The vault knows every exact value it holds, so it removes them from every response.
- **"Run a command with the secret" is the weakest kind** of use, because a command the agent writes
  can encode the value and hide it. It stays limited to fixed commands the founder approved.

## Dropped

Agent sandboxes (Claude's, Codex's, Grok's) as part of the design. They are fine to have on, but
LoopsVault must not depend on any of them.

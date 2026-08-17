---
title: Answer the three open architecture decisions
status: pending
category: task
created: 2026-08-17
related: [../HANDOFF.md]
---

# Three open decisions

**These block all build work.** They were presented at the end of the 2026-08-17 design session and
deliberately left open so the answer would be recorded in the LoopsVault project rather than in the
PitchPlus session where the design was born.

Full context for each is in [`../HANDOFF.md`](../HANDOFF.md) §11. Summarised here for the decision
itself.

---

## Decision 1: How does the proxy intercept HTTPS?

The biggest architecture fork. It decides how invasive LoopsVault is on the machine.

**Option A — Explicit local endpoint (recommended).**
Project code calls `http://127.0.0.1:14322/openrouter/v1/...` instead of
`https://openrouter.ai/v1/...`.
- No CA certificate installed anywhere.
- No TLS interception.
- The daemon can only ever see traffic you deliberately send it.
- Cost: each project's base URL is repointed once.

**Option B — MITM with a local CA.**
What Infisical's Agent Vault does. Install a CA certificate in the system trust store, set
`HTTPS_PROXY`, and everything is captured automatically.
- Zero per-project configuration.
- Cost: the daemon can decrypt **all** HTTPS traffic on the machine. A CA in your trust store is a
  serious thing to own, and it is a much larger blast radius if the daemon is ever compromised.

**Option C — Both, endpoint first.**
Ship A in v1, add opt-in B later for tools whose base URL cannot be changed.
- Never stuck.
- Cost: more work, two code paths.

**Answer:**

---

## Decision 2: Native Rust proxy, or wrap Agent Vault?

A timeline call: weeks versus days.

**Option A — Native Rust (recommended).**
Steal Agent Vault's design, write our own. Matches the stack decision, and the per-project cost
meter has to live inside the request path anyway, so wrapping would fight us.
- Cost: roughly 2 to 3 weeks to something solid.

**Option B — Wrap Agent Vault.**
Run their Go binary; build the catalog, meter, Touch ID and honeytokens around it.
- Working system in days.
- Cost: inherits Go and a preview-stage API. The meter becomes awkward without control of the
  request path.

**Option C — Wrap now, replace later.**
Prove the workflow on Agent Vault, swap in Rust once validated by real use.
- Lowest risk.
- Cost: some work done twice.

**Answer:**

---

## Decision 3: What is in v1?

**Option A — CLI first, GUI after (recommended).**
v1 is daemon + CLI + catalog + per-project attribution. Prove the proxy and the cost table against
real traffic. SwiftUI app, Touch ID and honeytokens in v2.

**Option B — Everything in v1.**
Complete system at once. Much longer before anything works, and design mistakes surface late.

**Option C — Thin slice, end to end.**
One key (OpenRouter), one project (`pitchplus_fast`), daemon + minimal GUI + Touch ID unlock.
Proves every layer including the Apple hardware, then broaden.

**Answer:**

---

## Pass criteria

All three answered in this file, then `HANDOFF.md` §11 updated to record the decisions and this
task flipped to `finished` by the founder.

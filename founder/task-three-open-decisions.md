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

**Answer: Option C, both, endpoint first.** (2026-08-17)

What this binds:
- v1 ships the explicit local endpoint only. No CA certificate is created, installed, or trusted by
  anything in v1.
- MITM is a later, opt-in, per-tool mode. It is off by default and the CA is installed only on an
  explicit founder command, never as a side effect of install or first run.
- Design constraint that follows: credential injection and exact host matching are written **once**,
  in a core both transports call. Two code paths for transport, one code path for the decision about
  which credential goes to which host. If that rule is broken, the wildcard bug this project fears
  most gets two chances to exist instead of one.

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

**Answer: Option A, native Rust.** (2026-08-17)

What this binds:
- Agent Vault is read as a reference design, not run as a dependency. No Go binary is shipped or
  wrapped.
- The 2 to 3 week estimate is accepted knowingly, with the revenue trade in HANDOFF.md §13 already
  acknowledged. Do not re-litigate it.
- Since we own the request path from the first commit, the per-project meter goes in at the same
  time as injection rather than being retrofitted around someone else's proxy.

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

**Answer: Option A, CLI first, GUI after.** (2026-08-17)

What this binds:
- v1 is daemon + CLI + catalog + explicit-endpoint proxy + per-project attribution. That is the
  whole of v1.
- SwiftUI app, Secure Enclave wrapping, Touch ID and honeytokens are v2. Honeytokens are cheap and
  high value, so they are the first thing pulled forward if v1 lands early.
- Known risk carried by this choice: the Apple hardware path (Secure Enclave, `biometryCurrentSet`,
  the break-glass export) stays unproven until v2. Mitigation is that v1's store encryption must be
  written so the master key is **wrapped by a pluggable unwrapper** from the first commit, with a
  file-based unwrapper in v1 and the Enclave unwrapper dropped in for v2. If v1 hardcodes how the
  key is unwrapped, v2 becomes a rewrite of the storage layer.
- Second consequence: the break-glass export is not a v2 feature. Its format is designed in v1,
  because a store written in v1 must still be recoverable after the Enclave lands.

---

## Pass criteria

All three answered in this file, then `HANDOFF.md` §11 updated to record the decisions and this
task flipped to `finished` by the founder.

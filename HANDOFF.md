# LoopsVault — Design Handoff

> **Read this entire file before doing anything.** It is the complete transfer of a design
> conversation held on 2026-08-17. Everything below was researched, verified, or decided.
> Do not re-research what is marked verified. Do not re-propose what is marked rejected.
>
> **The three decisions in §11 were answered on 2026-08-17. The build is unblocked.** Read §11 for
> the answers and the three constraints that follow from them before writing any code.

- **Project:** LoopsVault
- **Domain:** loopsvault.com
- **License:** MIT
- **Platform:** macOS first, Linux server support in the daemon from day one
- **Founder:** Jain Yagi
- **Design conversation date:** 2026-08-17
- **Origin:** a session rooted in `pitchplus_fast`, moved out deliberately because this is a
  separate product and does not belong in that repo

---

## 1. What LoopsVault is

A local, encrypted vault that lets AI coding agents **use** API keys and secrets **without ever
seeing their values**, while giving those agents a plaintext catalog of what keys exist and what
they are for.

One vault on one machine, serving all of the founder's projects (roughly ten active, in
`/Users/jain.jagi/Projects/`). One key per provider, not one key per project. Per-project usage
and cost attribution comes from the vault, not from the provider.

---

## 2. The problem it solves, stated precisely

The founder runs 8 to 10 projects, switching between them daily. Every project has its own `.env`
file. This produces four distinct problems, and it is worth keeping them separate because they
have different fixes:

1. **Redundancy.** The same OpenRouter, OpenAI, Anthropic, fal.ai, Stripe and Resend keys are
   copied into many `.env` files. Rotating one key means editing many files.
2. **Agents flail.** A global `PreToolUse` hook blocks `.env` access. The agent hits the wall,
   does not know what exists or what to do instead, and starts writing workaround scripts. This
   burns turns and produces nothing.
3. **Secrets leak into model context.** An agent reading a `.env` file pulls the values into its
   context window, which is uploaded to a model API and stored in a transcript. **This is the
   realistic threat, far more than laptop theft.**
4. **No per-project cost visibility.** One shared OpenRouter key across ten projects means no way
   to know which project is spending what.

**Measured during the design session:** the founder's own `~/.claude/scripts/block-env-access.sh`
denies any Bash command containing the literal string `.env`. A `find . -name ".env*"` command,
which lists file paths and reveals zero secret content, was **blocked**. The guard cannot
distinguish discovery from disclosure, and its denial message is a dead end that names no
alternative. That is the direct mechanical cause of problem 2.

---

## 3. The core mechanism: use without seeing

This is the heart of the design and the thing most likely to be misunderstood. **The agent never
enters the vault. There is no door on the agent's side.**

The flow for an outbound API call:

1. Agent constructs a request to OpenRouter with the credential field left as a placeholder.
2. Agent sends the request to the LoopsVault daemon.
3. Daemon matches the destination host against its policy, looks up the real credential,
   **writes the credential into the request itself**, and forwards it upstream.
4. Upstream responds. Daemon passes the response back to the agent.

The agent received what it needed. The key was never in the agent's process memory, never in its
terminal output, never in its context window. There is no moment at which it existed on the
agent's side of the boundary.

**The agent is not blindfolded inside the room. It is in a different room, sliding paper under
the door.**

Precedent: `ssh-agent` has worked exactly this way since 1995. It holds a private key and answers
signing challenges on the client's behalf. No SSH client has ever seen the key material.

**Corollary that must not be violated:** the agent never receives ciphertext and never receives a
decryption key. Giving it either would defeat the entire design. It receives a *reference*.

### Non-HTTP secrets

For anything not an outbound HTTPS call (a database password, a signing key), the daemon performs
the **operation** and returns only the result. The agent gets a capability, not a credential.
Note: Infisical's Agent Vault does not document how it handles this. **This gap is open and is
one of LoopsVault's differentiators.**

---

## 4. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  User session (uid 501, jain.jagi)                          │
│                                                             │
│   Claude Code / Codex / OpenClaw / project dev servers      │
│        │                                                    │
│        │  request with placeholder credential               │
│        │  + per-project token                               │
│        ▼                                                    │
│   ┌─────────────────┐                                       │
│   │ Unix domain     │  ← kernel-enforced permission boundary│
│   │ socket          │                                       │
└───┼─────────────────┼───────────────────────────────────────┘
    │                 │
┌───┼─────────────────┼───────────────────────────────────────┐
│   ▼                 │   Service account (_vaultd)           │
│  loopsvaultd (Rust, started by launchd at boot)             │
│    • credential injection into outbound requests            │
│    • per-project attribution + token/cost meter             │
│    • honeytoken tripwires + alarm                           │
│    • audit log (every use, every project, every timestamp)  │
│    • encrypted store, SQLite, file mode 0600 owned by _vaultd│
│    • master key wrapped by Secure Enclave, biometry-gated   │
└─────────────────────────────────────────────────────────────┘
    ▲
    │ (separate connection)
┌───┴─────────────────────────────────────────────────────────┐
│  LoopsVault.app (Swift + SwiftUI, menu bar)                 │
│    • add / rotate / delete keys (write-only, no read back)  │
│    • catalog editing: name, comment, expiry, projects       │
│    • per-project cost table                                 │
│    • Touch ID prompts, alarm notifications                  │
└─────────────────────────────────────────────────────────────┘
```

### The service account, explained (this was initially misunderstood)

`_vaultd` is a **background service account**, not a login account. The founder never switches to
it, never types a password for it, and never sees it. It is exactly what `_coreaudiod`,
`_calendar`, `_clamav` and 127 others already are on his machine.

**Verified on the founder's machine 2026-08-17:** 130 service accounts exist; only two accounts
(`jain.jagi` uid 501, `budankai` uid 502) can log in at all.

**Why it matters:** the store file is `0600` owned by `_vaultd`. When an agent running as
`jain.jagi` tries to read it, the refusal comes from the macOS kernel, not from LoopsVault code.
There is no policy to argue around and no logic bug to find. **This is the single change that
converts the design from policy-enforced to kernel-enforced.** Cost to the user: zero clicks,
zero passwords, zero seconds.

---

## 5. Security model, stated honestly

Do not oversell this to the founder. He asked directly for "by design, no way to see it," and the
honest answer has a boundary. Getting this wrong in either direction is bad: overselling breaks
trust when it fails, underselling makes him abandon a design that is genuinely strong.

### What the design genuinely prevents

- **A secret entering an agent's context window and being uploaded to a model API.** This is the
  real, daily, high-frequency threat and the design defeats it completely, because the agent
  never holds the value.
- **Secrets in a stolen laptop, a leaked backup, an iCloud sync, or an accidental `git commit`.**
  Encryption at rest handles these.
- **An agent going off-script or being prompt-injected into exfiltrating a key.** It cannot
  exfiltrate what it never had.
- **Reading the store file from the user account.** Kernel-enforced by the service account.
- **Decrypting the store on any other machine.** Secure Enclave wrapping binds it to this Mac.

### What it does not prevent

**Root on the machine.** If something has root, it can read the daemon's memory, and it can also
disable whatever detector you build. No application-level design changes this. The honest framing
for the founder: if something has root on your MacBook, the API keys are not the largest thing you
lost, and no code we write changes that. What we control is that the damage is **bounded and
loud**: keys scoped per project, spend capped per project, every use logged, honeytokens firing,
rotation one click away.

### The write-only decision

The founder wants GitHub-Secrets semantics: once saved, even he cannot read a value back. To
change one, you replace it.

Implement this. But be precise about what it is: **a UI policy, not a cryptographic guarantee.** A
machine that can decrypt in order to use can decrypt in order to display. GitHub can truly enforce
no-read-back because the secret lives on their server where the user has no root. On your own Mac
you always have root.

Its real value is behavioral and it is substantial: it kills the habit of peeking at a key and
pasting it into a terminal, a chat window, or an agent prompt. **That habit is where keys actually
leak in practice.**

**Mandatory consequence:** an encrypted break-glass export must exist. Without it, a corrupted
store or a Touch ID change means rotating every key across ten projects. See the Secure Enclave
gotcha in section 7.

### Strict host matching is the real attack surface

The proxy design is robust against an agent unsetting the proxy variable, because without the
proxy the agent has no credential and its own call simply fails. That is self-denial, not
exfiltration.

**The genuine risk is the opposite direction:** an agent routes a request to a host it controls,
and a loose injection rule attaches the real credential to it. **Host matching must be exact.
Never suffix matching, never wildcards.** This is where a bug would actually cost a key.

---

## 6. Feature set

### 6.1 The catalog (plaintext, agent-readable)

This is the piece that fixes the original complaint and the piece **no existing tool provides.**
For every entry:

| Field | Purpose |
|---|---|
| `name` | e.g. `OPENROUTER_API_KEY` |
| `provider` | e.g. `openrouter` |
| `comment` | what it is for, in plain language |
| `expiry` | optional, drives proactive rotation warnings |
| `projects[]` | which projects are permitted to use it |
| `shape` | e.g. `sk-or-v1-`, length, so agents can validate without values |
| `classification` | `secret`, `constant`, `public`, or `review` (see below) |
| `hosts[]` | exact hosts this credential may ever be sent to |
| `aliases[]` | other variable names that mean this same credential |

**`aliases[]` was added on 2026-08-17 after the inventory ran, and it is not
cosmetic.** The same Anthropic credential lives in these projects under two
different names, `ANTHROPIC_API_KEY` in six projects and `CLAUDE_API_KEY` in
four. Without aliases the vault either holds the same secret twice, which
recreates the rotation problem it exists to solve, or it forces a rename across
ten repositories before anything can be adopted. One entry with two names costs
nothing and makes adoption incremental. Expect more of these: the inventory also
found `GEMINI_*` alongside `GOOGLE_*` for the same provider.

**`classification` gained `public` for the same reason.** The inventory found 53
distinct names carrying `NEXT_PUBLIC_`, `VITE_`, `NUXT_PUBLIC_` or equivalent
prefixes. A framework compiles those into a browser bundle, so the value is
served to every visitor. They are not secrets no matter what they are named, and
a name like `NEXT_PUBLIC_..._SECRET` is a naming error rather than a credential.
Collapsing them into `constant` would lose that distinction, and it is worth
keeping because it is the one class the vault can refuse to store on principle.

Agents read this freely. They can answer "what keys exist, what are they for, which are expiring"
without any privileged operation.

**On `classification`:** the founder's own global `CLAUDE.md` carries a rule titled "A Value Is
Not An Environment Variable Until It Has To Be," with a measured case (findmyhooks, 2026-08-14)
where 46 required variables reduced to 32, of which **only 24 were real secrets**. Expect the
same here. Most of what lives in those ten `.env` files is a decided constant, not a secret.
**Classify before building, and the vault gets much smaller than it looks.** A reference preflight
implementation exists at `findmyhooks/scripts/env/preflight.ts`.

### 6.2 Per-project attribution and cost metering

The founder's strongest idea, and the reason the proxy architecture pays for itself twice.

**Why the proxy is the correct place:** it is the only component on the machine that sees the
project identity *and* the response body at the same time.

- Each project holds its own token for talking to the daemon. Project identity is cryptographic,
  not a self-declared string an agent could spoof.
- Usage is parsed out of the response in flight. OpenAI and OpenRouter return
  `usage: {prompt_tokens, completion_tokens}`. Anthropic returns
  `usage: {input_tokens, output_tokens}`.
- Multiply by a model price table for dollars. OpenRouter publishes model pricing via its API.

**This is what makes one key per provider viable.** The provider sees one key. The vault sees ten
projects. The founder gets his table without creating ten keys.

**Two honest limits to carry forward:**

- **Streaming needs a flag.** With SSE, usage arrives in the final chunk, and OpenAI only sends it
  when the request includes `stream_options: {include_usage: true}`. The daemon can inject that
  flag outbound. Solvable, not free.
- **Exact for LLM APIs, approximate for GPU APIs.** OpenRouter, OpenAI and Anthropic report tokens
  in the response body. **fal.ai and Replicate bill on compute time and generally do not.** The
  founder runs significant fal.ai traffic (Grok Imagine for PitchPlus Viral Hook), so he will get
  accurate call counts and rough attribution there, not exact dollars. OpenRouter can be made
  exact via a follow-up generation lookup.

**Optional bonus:** since the daemon already rewrites the outbound request, it can inject
`user: "<project>"` into the body. Providers use that field for their own tracking, so the same
split would appear in the provider dashboard too, still on a single key. Verify per provider at
build time.

### 6.3 Per-project spend caps

Falls out of the meter almost free, and **providers cannot offer it on a shared key.** "Stop
`42flows` at $50 this month" is impossible upstream and trivial here.

**Explicitly out of scope:** low-balance alerts for the provider account. OpenRouter already does
this and the founder said not to duplicate it.

### 6.4 Honeytokens and the alarm

The founder specifically asked for tamper detection. The strongest version is also the cheapest,
so build it early.

**Honeytokens.** Store a realistic but entirely fake credential with a tempting name, for example
`STRIPE_LIVE_SECRET_BACKUP`. No project references it. Nothing legitimate will ever touch it. If
it is ever requested, read, or appears in an outbound request, something is definitively wrong.
**Zero false positives**, which is rare enough in security to make this the first alarm to build.

**Behavioral alarms** layered on top:
- A credential requested for a host not in its `hosts[]` allowlist
- A credential used by a project not in its `projects[]` list
- An abnormal burst of requests
- Anything other than the daemon opening the store file

**Alarm response:** desktop notification, permanent audit log entry, and **one-click** revoke.
Keep revoke manual by default. An automatic revoke on a false positive takes production down at
3am.

**Honest limit to record:** file access and proxy anomalies are reliably detectable. Reading the
daemon's memory with root is not, because root can disable the detector too.

### 6.5 Harness adapters

Ship integrations, not just a CLI. The founder uses Claude Code, Codex, and OpenClaw.

The key insight from the origin problem: **a denial must name the next step.** An agent told
"blocked" writes workaround scripts. An agent told "run `loopsvault describe OPENROUTER_API_KEY`"
stops and does the right thing. The adapter should replace the founder's existing
`block-env-access.sh` dead-end message, and should allow pure discovery operations while still
blocking value reads.

---

## 7. Stack decision (decided, with rationale)

**Daemon: Rust. GUI: Swift + SwiftUI. They communicate over a Unix domain socket.**

- **Rust for the daemon** because it must run headless on Linux servers where SwiftUI does not
  exist. Single static binary, no runtime, no GC, clean cross-compilation. Ecosystem: `tokio` and
  `hyper` for the proxy, `rustls` for TLS, `rusqlite`, `age` for encryption.
- **Swift for the GUI** because Secure Enclave, `LocalAuthentication`, Touch ID, notifications,
  `launchd`, code signing and entitlements are all Apple framework territory. Driving them from
  Rust means bridging to Objective-C anyway.
- **The socket is the security boundary we already wanted.** Socket file permissions are
  kernel-enforced, so the `_vaultd` isolation comes for free rather than being bolted on.

**The founder rejected Node.js, JavaScript and React explicitly.** His stated reason was that JS is
"easily penetrable." That reasoning was corrected during the session and the correction should be
preserved, because it points at where effort actually belongs:

> Language choice does not make an application hard to penetrate. Rust eliminates memory-safety
> bugs, a real and valuable bug class, but does nothing about logic errors, bad key handling, or an
> attacker with root. **The security here comes from architecture: process isolation, the Secure
> Enclave, kernel-enforced permissions.**
>
> Rust is still correct, for a sharper reason specific to a secrets daemon: `zeroize` wipes keys
> from memory after use, and a secret can be wrapped in a type whose `Debug` implementation refuses
> to print it. **That structurally prevents a secret from ever reaching a log line.** In JavaScript
> that is a discipline you hope everyone follows; in Rust it is a compile error. A GC'd language
> with no destructors also leaves secrets resident in memory until collection, and
> `console.log(obj)` prints everything.

### Secure Enclave specifics (verified)

- Create the vault's master key inside the Secure Enclave with the
  [`biometryCurrentSet`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset)
  access control flag. The key never leaves the Enclave. **The Enclave declines to perform the
  unwrap without a live Touch ID**, which is hardware enforcement, not a software check root can
  patch out.
- **Constraint:** the Secure Enclave supports **NIST P-256 elliptic curve keys only**. No RSA, no
  symmetric keys. You therefore **cannot store an API key in the Enclave.** You use an Enclave key
  to unwrap the store's symmetric key. **The Enclave protects the door, not the contents.**
- **Critical gotcha:** with `biometryCurrentSet`, adding or removing a fingerprint, or changing the
  Mac's password, makes every biometry-protected item **permanently inaccessible**. This is Apple's
  intended behavior. **The encrypted break-glass export is therefore mandatory, not optional.**

**When to require Touch ID** (do not prompt on every request or the tool becomes unusable):

| Action | Touch ID |
|---|---|
| Normal API call through the proxy | No |
| Unlock vault at boot, or after idle timeout | Yes |
| Add, rotate, or delete a key | Yes |
| Any reveal or export | Yes |
| Clearing a honeytoken alarm | Yes |

### Platform floor

The founder proposed "M1 minimum, probably because of fingerprint hardware." **That reasoning is
incorrect and the constraint should be recorded as a choice, not a requirement.** Verified: Intel
Macs with the Apple T2 chip also have both Secure Enclave and Touch ID (MacBook Pro and Air 2018
to 2020, Mac mini 2018, iMac Pro 2017, Mac Pro 2019, iMac 2020).

Apple Silicon minimum is still defensible for a clean single-architecture testing matrix and
because Intel Macs are end-of-life. Just document it as a product decision.

---

## 8. Prior art: evaluated, do not re-research

| Tool | License | Verdict |
|---|---|---|
| [Infisical Agent Vault](https://github.com/Infisical/agent-vault) | MIT | **Closest prior art. 2.1k stars, 295 commits, active.** Standalone Go binary, no Infisical account required, local SQLite, web UI on :14321, proxy on :14322. Explicitly targets Claude Code and OpenClaw. **Steal the design.** Its own docs state agents should run on separate machines from the vault, which is exactly the single-machine case LoopsVault must solve via the service account. Does not do the catalog, per-project cost metering, Touch ID, or honeytokens. |
| [fnox](https://github.com/jdx/fnox) | MIT | Strong general secrets CLI from jdx (mise author). 20+ backends, `fnox exec` injects into a child process. **Injection, not brokering:** anything that can run `fnox exec -- npm start` can run `fnox exec -- printenv`. Good fallback for Tier B secrets. |
| [SOPS](https://github.com/getsops/sops) + [age](https://github.com/FiloSottile/age) | MPL-2.0 / BSD | **Already installed on the founder's machine.** Encrypts values, leaves keys plaintext. Good storage primitive, solves nothing about agents. |
| [llm-secrets](https://github.com/llmsecrets/llm-secrets) | AGPL-3.0 | Closest to the founder's literal spec (agent sees `$env[NAME]` plus descriptions). **Rejected:** requires a hardware WebAuthn authenticator, so it cannot run headless on a server. AGPL is also wrong for this project. Good ideas, wrong foundation. |
| [iron-proxy](https://hermes-agent.nousresearch.com/docs/user-guide/egress/iron-proxy) (Hermes) | - | Same credential-injection proxy pattern. Reference implementation for header-token providers (bearer, `x-api-key`, `api-key`, `x-goog-api-key`). |
| Infisical (full platform) | MIT core | Postgres + Redis + API server. Correct for a team, overkill for one laptop. |
| [dotenvx](https://github.com/dotenvx/dotenvx) | BSD-3 | Encrypted `.env`, keys visible. Storage only. |
| 1Password `op run` | Proprietary | Reference design for secret references in env files. Fails the open-source requirement. |
| HashiCorp Vault | BUSL | No longer open source. OpenBao is the OSS fork. Both far too heavy here. |

**Gap in the market, and LoopsVault's reason to exist:** every tool above solves storage and
injection. **None solves the catalog**, the per-project cost attribution, the harness adapters, or
non-HTTP secret brokering. That combination is the contribution.

---

## 9. Ideas considered and dropped (do not re-propose)

**Webcam face recognition for continuous verification.** The founder proposed using the laptop
camera plus computer vision to fingerprint his face, store the template locally, and require face
verification to open the vault.

**Dropped, but the instinct behind it was correct and was redirected into the Secure Enclave
design.** The requirement "a human must be physically present" is right. The webcam is the wrong
mechanism, for four reasons:

1. **It does not solve the case it was proposed for.** It was raised for the "attacker already has
   root" scenario. A camera check is software on that machine; root can patch it out, feed it a
   saved frame, or skip it and read memory directly. A lock the attacker can rewrite is not a lock.
2. **A webcam is 2D.** iPhone Face ID uses an infrared dot projector for depth and runs inside
   secure hardware. A MacBook camera is an ordinary RGB sensor, and 2D face matching is regularly
   defeated by a photo on a phone screen.
3. **Always-on camera costs are real:** permanent green indicator light, battery drain, and false
   rejections on every glance away or lighting change.
4. **A face is unrevokable.** A leaked API key rotates in thirty seconds. Storing a biometric
   template creates a permanent liability in order to protect temporary ones.

Touch ID plus a `biometryCurrentSet` Secure Enclave key delivers the same requirement with
hardware enforcement, no stored template, no camera, and no battery cost.

---

## 10. Verified facts about the founder's machine (2026-08-17)

Do not re-verify these; they were checked directly.

- **Hardware:** MacBook Pro, `MacBookPro17,1`, Apple M1, 8 cores.
- **Touch ID:** configured and active (`bioutil -r` reports biometrics enabled for unlock and
  Apple Pay).
- **Secure Enclave:** present (13 `AppleSEPManager` matches in `ioreg`).
- **Accounts:** 130 service accounts (`_`-prefixed); only two loginable accounts,
  `jain.jagi` (501) and `budankai` (502).
- **Already installed:** `sops`, `age`, `age-keygen`, `gpg`, Python `keyring`.
- **Not installed:** `op`, `direnv`, `dotenvx`, `infisical`, `pass`, `teller`, `chamber`, `vault`,
  `bao`.
- **Projects directory:** `/Users/jain.jagi/Projects/` with roughly 40 entries, around 10 actively
  worked.
- **Existing global hook:** `~/.claude/scripts/block-env-access.sh`, wired as a `PreToolUse` hook
  in `~/.claude/settings.json` for `Read|Edit|Write|NotebookEdit|Bash|Grep|Glob`. Blocks any Bash
  command containing the literal string `.env`, including pure discovery. Denial messages name no
  alternative. **This file is the first integration target and the quickest win available.**

**Not yet done:** a full inventory of variable names across all projects was **not** performed.
The founder's guard blocked it and it was not circumvented, deliberately. This inventory is step
one of the build and needs the founder's participation or an explicit adjustment to the guard.

---

## 11. Three Decisions (ANSWERED 2026-08-17)

**All three are decided. The build is unblocked.** They were presented on 2026-08-17 and
deliberately left open so the decision could be made in the LoopsVault project rather than in
PitchPlus. The founder answered them in the first LoopsVault session on the same day.

**The answers, in one place:**

| # | Decision | Answer |
|---|---|---|
| 1 | HTTPS interception | **Option C: both, endpoint first.** v1 is explicit local endpoint only. MITM is opt-in, per-tool, off by default, and lands after v1. |
| 2 | Proxy implementation | **Option A: native Rust.** Agent Vault is a reference design, not a dependency. |
| 3 | v1 scope | **Option A: CLI first, GUI after.** v1 is daemon + CLI + catalog + endpoint proxy + per-project attribution. |

**Three constraints that follow, and that a later session must not undo:**

1. **One injection core, two transports.** The endpoint path and the eventual MITM path share a
   single implementation of "which credential may go to which host." Exact host matching is written
   once. Duplicating it gives the one bug class that actually leaks a key two places to live.
2. **The master key unwrapper is pluggable from the first commit.** v1 uses a file-based unwrapper
   because Secure Enclave work is v2. If v1 hardcodes the unwrap path, v2 becomes a rewrite of the
   storage layer rather than a drop-in.
3. **The break-glass export format is designed in v1, not v2.** A store written in v1 must still be
   recoverable after the Enclave lands. See the `biometryCurrentSet` gotcha in §7.

Full reasoning for each answer is recorded in
[`founder/task-three-open-decisions.md`](founder/task-three-open-decisions.md). The original option
sets are kept below, unedited, so a later reader can see what was traded away.

### Decision 1: How does the proxy intercept HTTPS?

The biggest architecture fork.

- **Option A — Explicit local endpoint (recommended).** Project code calls
  `http://127.0.0.1:14322/openrouter/v1/...` instead of `https://openrouter.ai/v1/...`. No CA
  certificate installed, no TLS interception. The daemon can only see traffic deliberately sent to
  it. Cost: each project's base URL is pointed at the vault once.
- **Option B — MITM with a local CA.** What Agent Vault does. Install a CA certificate in the
  system trust store, set `HTTPS_PROXY`, capture everything with zero per-project config. Cost:
  the daemon can decrypt **all** HTTPS traffic on the machine, and a CA in the trust store is a
  serious thing to own.
- **Option C — Both, endpoint first.** Ship A in v1, add opt-in B later for tools whose base URL
  cannot be changed. More work, never stuck.

### Decision 2: Native Rust proxy, or wrap Agent Vault?

- **Option A — Native Rust (recommended).** Steal Agent Vault's design, write our own. Matches the
  stack decision, and the cost meter must live inside the request path anyway, so wrapping fights
  us. Cost: roughly 2 to 3 weeks to something solid.
- **Option B — Wrap Agent Vault.** Run their Go binary, build catalog, meter, Touch ID and
  honeytokens around it. Working system in days. Cost: inherits Go and a preview-stage API, and
  the meter becomes awkward without control of the request path.
- **Option C — Wrap now, replace later.** Prove the workflow on Agent Vault, swap in Rust once
  validated by real use. Lowest risk, some work done twice.

### Decision 3: What is in v1?

- **Option A — CLI first, GUI after (recommended).** v1 is daemon plus CLI plus catalog plus
  per-project attribution. Prove the proxy and the cost table against real traffic. SwiftUI app,
  Touch ID and honeytokens in v2.
- **Option B — Everything in v1.** Complete system at once. Much longer before anything works and
  design mistakes surface late.
- **Option C — Thin slice, end to end.** One key (OpenRouter), one project (`pitchplus_fast`),
  daemon plus minimal GUI plus Touch ID unlock. Proves every layer including Apple hardware, then
  broaden.

---

## 12. Build order (decisions have landed, this is live)

The v1 line sits after step 5. Steps 1 to 5 are v1. Steps 6 to 9 are v2, with one caveat noted
below.

1. **Fix `block-env-access.sh` first.** Allow pure discovery, make denials name the next step. Ten
   minutes, no dependencies, and it removes the daily friction immediately.
2. **Inventory and classify.** Every variable name across all projects, which projects share it,
   secret versus decided constant. Output is the first catalog. **Requires founder participation
   because of the guard.** This is the work that makes everything after it easy.
3. **Daemon skeleton:** encrypted store, service account, launchd plist, Unix socket, catalog read
   API.
4. **Proxy and injection**, explicit local endpoint only, with exact host matching from the very
   first commit and a single injection core the later MITM transport will reuse.
5. **Per-project tokens and the meter.**

   *(end of v1)*

6. **Honeytokens and alarms.** Cheap and high value, so this is the first thing pulled forward into
   v1 if the schedule allows. It is listed under v2 only because Decision 3 drew the line there.
7. **Harness adapters** for Claude Code, Codex, OpenClaw.
8. **SwiftUI app**, Secure Enclave wrapping, Touch ID, break-glass export. The export **format** is
   designed during v1 even though the app is v2, because a v1 store must stay recoverable.
9. **Opt-in MITM transport**, per-tool, off by default, reusing the v1 injection core.
10. **Linux server path** for the daemon.

---

## 13. Founder working rules that apply here

From `~/.claude/CLAUDE.md`. The full file governs; these are the ones this project will hit.

- **Do not assume anything.** Verify state before acting on it. Read what the system says rather
  than inferring what it might say.
- **Do not hand verification work to the founder.** If it can be verified with a tool, verify it
  and report the result. Founder time is for credentials, judgment, and physical-world actions.
- **Never delegate testing or verification to a sub-agent.** No headless browsers in sub-agent
  briefs, ever. The lead agent verifies.
- **Two-branch git:** `develop` and `main` only, no feature branches. Commit substantive work
  automatically without asking. **Never push, never merge a PR.** The founder pushes.
- **Never add `Co-Authored-By` to commits.**
- **Never use em dashes** anywhere, including code comments and commit messages. Never use the
  phrase "load-bearing."
- **A value is not an environment variable until it has to be.** Only secrets and values that
  genuinely differ between existing deployments. Everything else is a constant in source. **This
  rule is directly relevant to the catalog's `classification` field.**
- **Every project has a `founder/` directory** with `INDEX.md` and `TODO.md`. Scaffolded here
  already. Agents never set a task to `finished`; only the founder does.
- **Design a strong foundation that generalizes.** Find the upstream structural variable, not the
  per-case boolean.

### Revenue context, stated once

The founder's primary mandate on PitchPlus is $5,000/mo MRR. On 2026-08-17 he was at **$284.67
month-to-date with 14 days left**. LoopsVault is developer infrastructure and does not move that
number. He chose to proceed with full knowledge of that, so **do not re-litigate it.** It is
recorded here only so scope decisions stay honest about the trade: step 1 of the build order takes
minutes, the full system takes weeks.

---

## 14. Sources

- [Infisical Agent Vault (repo)](https://github.com/Infisical/agent-vault)
- [Agent Vault announcement](https://infisical.com/blog/agent-vault-the-open-source-credential-proxy-and-vault-for-agents)
- [iron-proxy, Hermes Agent](https://hermes-agent.nousresearch.com/docs/user-guide/egress/iron-proxy)
- [fnox](https://github.com/jdx/fnox)
- [llm-secrets](https://github.com/llmsecrets/llm-secrets)
- [SOPS](https://github.com/getsops/sops) / [age](https://github.com/FiloSottile/age)
- [dotenvx](https://github.com/dotenvx/dotenvx)
- [SecureEnclave.P256, Apple](https://developer.apple.com/documentation/cryptokit/secureenclave/p256)
- [kSecAttrTokenIDSecureEnclave, Apple](https://developer.apple.com/documentation/security/ksecattrtokenidsecureenclave)
- [Apple T2 Security Chip overview (PDF)](https://www.apple.com/mideast/mac/docs/Apple_T2_Security_Chip_Overview.pdf)
- [Apple biometric security](https://support.apple.com/guide/security/biometric-security-sec067eb0c9e/web)

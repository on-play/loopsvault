---
title: Run the first real credential through the vault
status: pending
category: task
created: 2026-08-19
related: [../README.md, task-service-account.md, task-guard-data-vs-path.md]
---

# The first real call

**v1 has worked since 2026-08-17 and has still never brokered a real credential.** Everything is
proven against fake keys. Until one real project runs through it, it is well-tested theory.

Everything below is staged and waiting. Worked out with the 42flows.com session on 2026-08-19; they
hold the matching record on their side.

---

## Founder-only, and the whole thing is blocked on the first one

### 1. Paste the key

```
~/Projects/loopsvault/target/release/loopsvault set OPENROUTER_API_KEY
```

Prompts without echo, confirms by shape only ("40 bytes, Token"), never shows it again. I will not
handle it and neither will any other session; the 42flows session was told explicitly not to read it
out of an env file to "help".

### 2. One Coolify question, one screen

**Does Coolify pass env into the docker BUILD, or only at runtime?**

- If build: the change needs a **rebuild**, and a restart alone will look like it did nothing.
- If runtime with `NUXT_`-prefixed rows already set: a **restart** is enough.

42flows found no build `args:` in the compose file and no prefixed names in the repo, which points
at build-time, but they refused to hand that over as fact and they were right to.

**This is deferred entirely if step 1 runs locally first**, which is the current plan.

---

## Staged on my side, nothing left to do

- `~/.loopsvault/` initialised, master key `0600`.
- Catalog entry for `OPENROUTER_API_KEY` generated from the inventory, scoped to the 7 projects that
  use it, host pinned to `openrouter.ai` exactly.
- Release binaries built, 3.0M and 3.6M.
- Store is empty. It is created by the first `set`.
- Project token for `42flows.com` is **not** issued yet, deliberately: there is no point issuing a
  token to call a vault with no key in it. One command once step 1 lands.

## The run itself, two steps in one sitting

**Step 1, proves the plumbing.** 42flows sets the base URL and adds the token header to its three
call sites. One real call through `server/services/ai-client.ts:81`. Not a loop.

```
NUXT_OPENROUTER_BASE_URL=http://127.0.0.1:14322/openrouter/api/v1
```

**The `NUXT_` prefix is not optional and this is the trap that nearly cost a debugging cycle.** Nuxt
bakes `runtimeConfig` at build time; only the prefixed name overrides at runtime. Setting the plain
name would have left the app calling `openrouter.ai` directly, every call succeeding, and this
daemon showing zero traffic. That is indistinguishable from a proxy silently dropping requests, and
the hunt would have happened on the wrong side of the wire.

The same trap has a second form: **in local dev the plain name DOES work**, because `nuxt.config.ts`
is evaluated at dev-server start. So a local test with the plain name passes and then no-ops in
production. Prefixed name in both environments, always.

**Step 2, proves the actual point.** Blank the key and run the same call. If the app works with no
key in its own environment, the claim is demonstrated rather than asserted.

```
NUXT_OPENROUTER_API_KEY=
```

**Set to empty, not deleted.** An unset var falls back to the value baked in at build; an explicit
empty string wins because it is not nullish. Deleting the row would produce a passing keyless test
that proves the opposite of what it claims.

One code change is required in step 2: `server/services/openrouter-pricing-sync.ts:47-51`
short-circuits on an empty key and never issues a request. Under the vault its premise is gone,
since the daemon supplies the credential.

## Known before we start, so nothing is mistaken for a proxy bug

- **Latency**: no per-call baseline exists in that project, so 42flows will measure it: six calls,
  four measured, alternating direct and proxied, both paths warmed first. Reporting absolute numbers
  and the delta, and saying so explicitly if the delta is inside run-to-run variance.
- **Scope of the result**: if the numbers are good, the honest claim is "good for non-streaming
  JSON", not "good".
- **Gemini is a later phase and has a real blocker.** The daemon buffers responses rather than
  relaying them. Gemini's streaming fallback exists because long generations fail, so buffering
  turns it into a second identical non-streaming attempt: it keeps running and quietly stops
  rescuing what it was added to rescue, presenting as the model failing. **Fix incremental relay in
  the daemon before adopting Gemini, not after.**
- **fal is deferred.** Queue-based `subscribe` plus fal's own `proxyUrl` protocol is a different
  shape and forcing it would be premature generality.

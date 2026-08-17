---
title: Three calls the inventory surfaced
status: pending
category: task
created: 2026-08-17
related: [task-inventory-and-classify.md, ../HANDOFF.md]
---

# The inventory ran. Three things need you.

Full report is at `catalog/INVENTORY.md`, which is **gitignored** because it names every project
and every credential on this machine and this remote is public. Regenerate any time:

```
bash tools/inventory/collect.sh > catalog/inventory.tsv
bash tools/inventory/report.sh catalog/inventory.tsv > catalog/INVENTORY.md
```

The numbers: 28 projects, 72 env files, 1902 definitions, 429 distinct names in real files. Of
those, 100 secrets, 143 constants, 53 public-by-construction, **133 needing your call**.

The premise checked out with numbers rather than impressions. `OPENROUTER_API_KEY` is in 7 projects,
`OPENAI_API_KEY` in 7, `GEMINI_API_KEY` in 7, `ANTHROPIC_API_KEY` in 6, `DATABASE_URL` in 15.

---

## 1. There is a stale credential sitting in a live env file

`CLAUDE_API_KEY_OLD` exists in a real env file. Either it is dead, in which case it should be
deleted today and not carried into the vault, or it is a fallback that is still live, in which case
it is an un-rotated credential with `OLD` in its name.

**This is the only item here that is a security question rather than a design one.** It costs a
minute and does not depend on anything else being built.

**Needed from you:** delete it, or tell me it is still in use.

## 2. Two names for one Anthropic key

`ANTHROPIC_API_KEY` in 6 projects, `CLAUDE_API_KEY` in 4. Same provider, same credential, different
name. `GEMINI_*` alongside `GOOGLE_*` looks like the same story.

I have already added `aliases[]` to the catalog spec in HANDOFF.md 6.1 so the vault can hold one
entry with two names. Without it the vault stores the same secret twice, which recreates the exact
rotation problem it exists to solve, or it forces a rename across ten repos before you can adopt
anything.

**Needed from you:** nothing blocking. Flagging it because if you would rather normalise the names
across projects than carry aliases forever, that is a call worth making before the catalog is
populated rather than after.

## 3. The 133 "review" names

The classifier is deliberately conservative: it only calls something a secret when the name says so.
133 distinct names are genuinely ambiguous. Examples: `GOOGLE_CLIENT_ID` (paired with a secret, but
the ID itself is public), `REDIS_HOST`, `ADMIN_EMAIL`, `FRONTEND_URL`, `CLOUDFLARE_ACCOUNT_ID`,
`SPOTIFY_REDIRECT_URI`, `RUNPOD_WHISPER_ENDPOINT_ID`.

Most of these are almost certainly constants under your own rule, which would shrink the vault
further. But guessing wrong in the constant direction puts a credential in source, so I am not
guessing.

**Needed from you:** one pass through the review list in `catalog/INVENTORY.md`. It does not block
the daemon, and it does block populating the catalog with real entries.

---

## One piece of good news for Decision 1

`OPENROUTER_BASE_URL` and `OPENROUTER_CHAT_COMPLETIONS_URL` **already exist** in these projects. The
explicit-local-endpoint approach you chose needs exactly that override point, and in at least some
projects the wiring is already there rather than needing to be added. v1 adoption is cheaper than
the handoff assumed.

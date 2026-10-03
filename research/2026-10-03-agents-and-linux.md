# Research, 2026-10-03: every agent, Linux, and who else is doing this

Done when the founder started coding on a Linux machine and asked what LoopsVault should become so
that it is the first thing anyone installs. Checked against primary docs and `gh api` on the day;
anything not checked is marked.

## 1. Claude Code now has its own small version of the core idea

`sandbox.credentials` with `"mode": "mask"`: shell commands Claude runs inside its sandbox see a
placeholder, and Claude's network proxy puts the real value back on requests to listed hosts.
Read in full at https://code.claude.com/docs/en/sandboxing#mask-credentials. Limits, from that page:

- Only shell commands inside Claude's sandbox. Claude's own file tools, MCP servers and hooks run
  outside it.
- Needs `network.tlsTerminate`, marked experimental, so Claude's proxy decrypts the traffic.
- The real value still lives in an env var or a file on disk.
- Claude only. Codex, Cursor, Grok and the production app get nothing from it.

So it does not replace LoopsVault. LoopsVault can write these settings for Claude as one adapter.

Also from that page: inside Claude's Linux sandbox, a direct connection to `127.0.0.1` does not
reach the host, so calls to the vault need an exception. The founder has since said to drop
sandboxes from the design (see `founder/vision-use-not-have.md`), so this only matters if one is on.

## 2. How each agent takes rules, hooks and status lines

| Agent | Block `.env` reads | Hook before a tool runs | Global instructions | Status line with 5h and weekly |
|---|---|---|---|---|
| Claude Code | `permissions.deny`, covers `cat`/`head`/`sed`, not scripts or `grep -r` | `PreToolUse` | `~/.claude/CLAUDE.md`, reads `AGENTS.md` | Yes, `rate_limits.five_hour` / `seven_day` (verified; this Mac already uses it) |
| Codex | Permission profile `"**/*.env" = "deny"` (beta) | `PreToolUse`, same format as Claude | `~/.codex/AGENTS.md` | Built-in items `five-hour-limit`, `weekly-limit` (not checked against OpenAI docs) |
| Grok Build (xAI) | `[permission] deny` | **Loads Claude's and Cursor's hook files directly** | `~/.grok/rules/`, reads `CLAUDE.md` and `AGENTS.md` | Custom command, no limit fields |
| Cursor | `.cursorignore` does not stop the terminal | `beforeShellExecution`, `beforeReadFile`, **also loads Claude's hook files** | App setting, `AGENTS.md` | CLI only, no limit fields found |
| Gemini CLI | Policy TOML | `BeforeTool`, close to Claude's but different tool names | `~/.gemini/GEMINI.md` | Footer settings only |
| Copilot CLI | `--deny-tool` | `PreToolUse` in Claude mode | `~/.copilot/copilot-instructions.md`, `AGENTS.md` | Quota toggle |
| opencode | Denies `*.env` by default | JS plugin only | `~/.config/opencode/AGENTS.md`, falls back to `~/.claude/CLAUDE.md` | Not found |

What this means: **one Claude-format guard covers Claude, Codex, Grok, Cursor and Copilot**, and
Gemini needs a thin translation. `AGENTS.md` is read by nearly everyone. There is no shared ignore
file in practice, and the only cross-vendor hook spec (`kaija/agent-hook-spec`) has no adopters.

## 3. Who else is in this space

**Copy rules into every agent** (crowded, none of them enforce anything):
- rulesync (MIT, ~1.5k stars, active): rules, ignore, MCP, hooks, permissions, 70+ tools. Node.
- ruler (MIT, ~2.9k stars): rules, MCP, skills. No hooks or permissions.
- dotagents: symlinks one folder into every agent. Stale since February.

**Stop agents doing bad things:**
- nono (Apache-2.0, ~4.3k stars, active): sandbox plus a credential proxy for many agents, Linux and
  macOS. The closest competitor. No plaintext catalog, no per-project cost.
- cc-safety-net (MIT, ~1.6k stars): parses commands before they run, blocks `.env` and SSH reads
  across 14 agents. Pattern matching, the key still sits on disk.
- destructive_command_guard (custom licence, ~6k stars): Rust, aimed at destructive commands.
- psst, secretspec, tene, envkeep: put the value into the process environment, where `env` prints it.
- blindvault: same idea as LoopsVault, 3 stars.

**Evidence the problem is real:**
- Claude Code #59094: an agent printed live brokerage keys from a `.env` despite a written rule
  against it. Closed as not planned. The user rotated four key pairs.
- Cursor forum: the default `.env` ignore only covers indexing, not the agent reading the file.
- Codex #30971 (open): shell snapshots save secret environment values to disk in plain text.

**Nobody does all three of these:** keep the secret out of every agent, the same rules in every
agent, and per-project cost. That is the gap.

## 4. Running the vault on Linux

- Run the daemon as its own system user (`loopsvault`) under systemd. Another uid already stops a
  process running as the founder from reading its files or its memory. Only root gets past it.
- Use a fixed system user, not `DynamicUser`, so the CLI can check the socket really belongs to the
  vault before talking to it.
- The CLI and daemon check each other's uid on the socket (`SO_PEERCRED`, built into tokio).
- The master key: `systemd-creds encrypt` ties it to the machine's TPM chip when there is one. With
  no TPM it is root-only on disk, so disk encryption is what protects a stolen laptop.
- Desktop keyrings (GNOME Keyring, KWallet) let any process running as the founder read unlocked
  items. Not usable for the vault key.
- Fingerprint as the Touch ID equivalent: a polkit prompt, which shows fingerprint when the distro
  has it set up.
- Install with one sudo, like ollama's installer, but **never** add the founder to the vault's group,
  which ollama does and which would hand the agent access.

A full systemd unit with the hardening settings is in the research notes of the 2026-10-03 session
and will land as a file when the Linux install is built.

## 5. This Mac, as found

- The status line the founder wants already exists in `~/.claude/settings.json`.
- The guard scripts live in two copies: `~/.claude/scripts/` and `~/.codex/claude-context/legacy/scripts/`
  (copied 2026-09-17). Same logic today apart from one path, but a fix to one never reaches the other.
- `~/.codex/AGENTS.md` still says Claude is excluded (2026-09-23), which is no longer the case.
- 15 commits on `main` are not pushed, so a machine installing from GitHub gets the 19 August code.

## Not verified

Codex status line item names; Gemini policy syntax; Cursor and Copilot status line contents; nono's
kernel mechanism; Ubuntu 22.04's systemd version.

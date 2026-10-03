#!/usr/bin/env bash
# Print the facts a LoopsVault install on this Linux machine depends on.
#
# Read-only. Prints names, versions, paths and yes/no answers. It never prints
# the value of an environment variable or the contents of any env or key file.
# Run it as your normal user (not sudo) and paste the whole output back.

set -u

say()  { printf '%-28s %s\n' "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1 && echo yes || echo no; }
ver()  { command -v "$1" >/dev/null 2>&1 && ("$@" 2>/dev/null | head -1) || echo "not installed"; }

echo "== machine"
. /etc/os-release 2>/dev/null
say "distro"            "${PRETTY_NAME:-unknown}"
say "arch"              "$(uname -m)"
say "kernel"            "$(uname -r)"
say "user / uid"        "$(id -un) / $(id -u)"
say "sudo available"    "$(have sudo)"
say "systemd"           "$(systemctl --version 2>/dev/null | head -1 || echo none)"
say "systemd-creds"     "$(have systemd-creds)"
say "TPM device"        "$([ -e /dev/tpmrm0 ] && echo yes || echo no)"
say "disk encryption"   "$(lsblk -o TYPE 2>/dev/null | grep -q crypt && echo 'LUKS seen' || echo 'none seen')"
say "ptrace_scope"      "$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo n/a)"
say "userns restricted" "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo n/a)"
say "fingerprint (fprintd)" "$(have fprintd-list)"
say "desktop session"   "${XDG_CURRENT_DESKTOP:-none}"

echo
echo "== tools"
for t in git jq curl bwrap socat cc gcc docker node python3; do say "$t" "$(have $t)"; done
say "cargo"             "$(ver cargo --version)"
say "rustc"             "$(ver rustc --version)"

echo
echo "== agents installed"
for t in claude codex gemini cursor-agent grok opencode copilot aider amp kiro-cli; do
  say "$t" "$(ver $t --version)"
done

echo
echo "== agent config folders present"
for d in ~/.claude ~/.codex ~/.gemini ~/.cursor ~/.grok ~/.config/opencode ~/.copilot ~/.config/amp ~/.kiro ~/.loopsvault; do
  say "$d" "$([ -e "$d" ] && echo yes || echo no)"
done

echo
echo "== Claude Code setup (structure only, no values)"
S=~/.claude/settings.json
if [ -f "$S" ] && command -v jq >/dev/null; then
  jq -r '
    "hooks: " + ((.hooks // {}) | to_entries | map(.key + "=" + ([.value[].hooks[].command] | join(","))) | join("  ")),
    "deny rules: " + ((.permissions.deny // []) | join("  ")),
    "status line set: " + (if .statusLine then "yes" else "no" end),
    "sandbox enabled: " + ((.sandbox.enabled // false) | tostring),
    "top-level keys: " + (keys | join(","))' "$S"
  ls ~/.claude/scripts ~/.claude/hooks 2>/dev/null | sed 's/^/  /'
else
  echo "no ~/.claude/settings.json (or jq missing)"
fi

echo
echo "== Codex setup (structure only)"
[ -f ~/.codex/hooks.json ] && echo "hooks.json present" || echo "no hooks.json"
[ -f ~/.codex/config.toml ] && grep -E '^\[' ~/.codex/config.toml | head -20
[ -f ~/.codex/AGENTS.md ] && echo "AGENTS.md: $(wc -l < ~/.codex/AGENTS.md) lines"

echo
echo "== projects folder"
for d in ~/Projects ~/projects ~/code ~/src ~/dev; do
  [ -d "$d" ] && say "$d" "$(find "$d" -maxdepth 1 -mindepth 1 -type d | wc -l) folders"
done

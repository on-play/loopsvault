#!/bin/bash
# 360-degree leak sweep.
#
# Plants a canary value in a throwaway vault, exercises every command and every
# route, and then checks whether the canary appears anywhere it should not:
# stdout, stderr, the store, the config, the daemon log, the token files, the
# audit, the usage rollup, backups and temp files.
#
# The point is that this is EXHAUSTIVE and REPEATABLE rather than an inspection.
# A leak found by reading code is found once; a leak found by this is found
# every time someone adds a route.
#
# Uses its own config, its own port and its own directory. Touches nothing real.
#
#   bash tools/leak-sweep.sh

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LV="$ROOT/target/release/loopsvault"
LVD="$ROOT/target/release/loopsvaultd"
PORT=14377
W="$(mktemp -d "${TMPDIR:-/tmp}/loopsvault-leak.XXXXXX")"
CFG="$W/config.json"
DAEMON_PID=""

# Distinctive enough that a substring match cannot be a coincidence, and
# obviously fake so it can never be mistaken for a real credential.
CANARY="FAKE-CANARY-9d3f7a1e-must-never-appear-anywhere"
TOKEN_CANARY=""

cleanup() {
  [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null
  rm -rf "$W"
}
trap cleanup EXIT

leaks=0
checked=0
clean() {
  checked=$((checked + 1))
  local where="$1" text="$2"
  if printf '%s' "$text" | grep -qF "$CANARY"; then
    leaks=$((leaks + 1)); printf '  LEAK   %s\n' "$where"
  else
    printf '  clean  %s\n' "$where"
  fi
}
clean_file() {
  checked=$((checked + 1))
  local where="$1" path="$2"
  if [ ! -e "$path" ]; then printf '  n/a    %s (absent)\n' "$where"; return; fi
  if grep -qF "$CANARY" "$path" 2>/dev/null; then
    leaks=$((leaks + 1)); printf '  LEAK   %s\n' "$where"
  else
    printf '  clean  %s\n' "$where"
  fi
}

echo "Setting up a throwaway vault."
"$LV" --config "$CFG" init >/dev/null 2>&1
python3 - "$CFG" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
c["catalog"]["entries"] = [{
    "name": "CANARY_API_KEY", "aliases": ["CANARY_ALIAS"], "provider": "openrouter",
    "comment": "leak sweep canary", "projects": ["sweep"],
    "classification": "secret", "hosts": ["openrouter.ai"],
    "placement": {"kind": "header", "header": "authorization", "scheme": "Bearer"},
}, {
    "name": "HONEY_TRAP_KEY", "provider": "stripe", "comment": "honeytoken",
    "projects": [], "classification": "secret", "hosts": [], "honeytoken": True,
}]
c["providers"] = {"openrouter": {"upstream": "https://openrouter.ai", "credential": "CANARY_API_KEY"}}
json.dump(c, open(sys.argv[1], "w"), indent=2)
PY

printf '%s\n' "$CANARY" | "$LV" --config "$CFG" set CANARY_API_KEY > "$W/set.out" 2>&1
"$LV" --config "$CFG" project add sweep > "$W/projadd.out" 2>&1
TOKEN_PATH=$(head -1 "$W/projadd.out")
TOKEN=$(cat "$TOKEN_PATH" 2>/dev/null)

"$LVD" --config "$CFG" --bind "127.0.0.1:$PORT" > "$W/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 0.2; done

echo
echo "=== CLI output (stdout and stderr together) ==="
clean "loopsvault set"        "$(cat "$W/set.out")"
clean "loopsvault project add" "$(cat "$W/projadd.out")"
clean "loopsvault ls"          "$("$LV" --config "$CFG" --daemon "http://127.0.0.1:$PORT" ls 2>&1)"
clean "loopsvault describe"    "$("$LV" --config "$CFG" --daemon "http://127.0.0.1:$PORT" describe CANARY_API_KEY 2>&1)"
clean "describe by alias"      "$("$LV" --config "$CFG" --daemon "http://127.0.0.1:$PORT" describe CANARY_ALIAS 2>&1)"
clean "loopsvault usage"       "$("$LV" --config "$CFG" --daemon "http://127.0.0.1:$PORT" usage 2>&1)"
clean "loopsvault verify"      "$("$LV" --config "$CFG" --daemon "http://127.0.0.1:$PORT" verify CANARY_API_KEY 2>&1)"
clean "loopsvault project ls"  "$("$LV" --config "$CFG" project ls 2>&1)"
clean "set --help"             "$("$LV" --config "$CFG" set --help 2>&1)"
clean "rm of a missing name"   "$("$LV" --config "$CFG" rm NOT_THERE 2>&1)"
clean "set with a bad name"    "$(printf 'x\n' | "$LV" --config "$CFG" set "not-a-name" 2>&1)"

echo
echo "=== HTTP routes ==="
for path in /healthz /catalog /catalog/CANARY_API_KEY /catalog/CANARY_ALIAS /catalog/HONEY_TRAP_KEY /usage /audit /catalog/NOPE; do
  clean "GET $path" "$(curl -s -H "x-loopsvault-project-token: $TOKEN" "http://127.0.0.1:$PORT$path")"
done
clean "proxy denial, no token"   "$(curl -s -X POST "http://127.0.0.1:$PORT/openrouter/v1/chat/completions")"
clean "proxy denial, bad token"  "$(curl -s -X POST -H "x-loopsvault-project-token: lvp_$(printf '0%.0s' $(seq 1 64))" "http://127.0.0.1:$PORT/openrouter/v1/chat/completions")"
clean "proxy denial, unknown provider" "$(curl -s -X POST -H "x-loopsvault-project-token: $TOKEN" "http://127.0.0.1:$PORT/nosuch/v1/x")"
clean "honeytoken via proxy"     "$(curl -s "http://127.0.0.1:$PORT/catalog/HONEY_TRAP_KEY")"

echo
echo "=== a real proxied call, response and audit afterwards ==="
clean "upstream response body" "$(curl -s -H "x-loopsvault-project-token: $TOKEN" "http://127.0.0.1:$PORT/openrouter/api/v1/auth/key")"
clean "audit after a real call" "$(curl -s "http://127.0.0.1:$PORT/audit")"
clean "usage after a real call" "$(curl -s "http://127.0.0.1:$PORT/usage")"

echo
echo "=== files on disk ==="
clean_file "the encrypted store"  "$W/vault.store"
clean_file "the config"           "$CFG"
clean_file "the master key"       "$W/master.key"
clean_file "the daemon log"       "$W/daemon.log"
clean_file "the project token"    "$TOKEN_PATH"

echo
echo "=== the break-glass export (encrypted, must not be plaintext) ==="
printf 'a-long-enough-passphrase\n' | "$LV" --config "$CFG" export "$W/export.age" > "$W/export.out" 2>&1
clean      "export command output" "$(cat "$W/export.out")"
clean_file "the export file"       "$W/export.age"

echo
echo "=== every file the run produced, swept blind ==="
found=$(grep -rlF "$CANARY" "$W" 2>/dev/null | grep -v "^$W/export.age$" || true)
checked=$((checked + 1))
if [ -n "$found" ]; then
  leaks=$((leaks + 1))
  echo "  LEAK   the canary is readable in:"
  printf '    %s\n' $found
else
  echo "  clean  no file under the work directory contains it"
fi

echo
echo "=== the token must not be recoverable from anywhere but its own file ==="
if [ -n "$TOKEN" ]; then
  checked=$((checked + 1))
  if grep -qF "$TOKEN" "$CFG" 2>/dev/null; then
    leaks=$((leaks + 1)); echo "  LEAK   the config holds the raw project token"
  else
    echo "  clean  the config holds only a hash of the token"
  fi
  checked=$((checked + 1))
  if curl -s "http://127.0.0.1:$PORT/audit" | grep -qF "$TOKEN"; then
    leaks=$((leaks + 1)); echo "  LEAK   the audit holds the raw project token"
  else
    echo "  clean  the audit holds no token"
  fi
fi

echo
echo "================================"
printf 'surfaces checked: %d,  leaks: %d\n' "$checked" "$leaks"
[ "$leaks" -eq 0 ] && echo "NO LEAKS" || echo "LEAKS FOUND"
exit "$leaks"

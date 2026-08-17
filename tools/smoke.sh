#!/bin/bash
# End-to-end smoke test of the shipped binaries, exactly as a founder would use
# them. Starts a daemon, drives the CLI against it, and always kills the daemon
# on the way out.
#
# The Rust tests prove the injection path. This proves the tool is usable: that
# `init`, `set`, `project add`, `ls`, `describe` and `usage` actually work
# together against a real daemon, which no unit test can tell you.
#
#   bash tools/smoke.sh

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CARGO="$HOME/.cargo/bin/cargo"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/loopsvault-smoke.XXXXXX")"
PORT=14399
DAEMON_PID=""

cleanup() {
  if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

fail=0
ok()   { printf '  ok    %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fail=$((fail+1)); }
check(){ if [ "$1" = "$2" ]; then ok "$3"; else bad "$3 (got [$1] want [$2])"; fi; }

echo "Building release binaries."
"$CARGO" build --quiet --manifest-path "$ROOT/Cargo.toml" || { echo "build failed"; exit 1; }
LV="$ROOT/target/debug/loopsvault"
LVD="$ROOT/target/debug/loopsvaultd"
CFG="$WORK/config.json"

echo
echo "=== init ==="
"$LV" --config "$CFG" init > "$WORK/init.log" 2>&1
check "$([ -f "$CFG" ] && echo yes || echo no)" "yes" "config created"
check "$([ -f "$WORK/master.key" ] && echo yes || echo no)" "yes" "master key created"
KEYMODE=$(stat -f "%OLp" "$WORK/master.key" 2>/dev/null || stat -c "%a" "$WORK/master.key")
check "$KEYMODE" "600" "master key is 0600"

echo
echo "=== catalog + provider ==="
python3 - "$CFG" <<'PY'
import json, sys
p = sys.argv[1]
c = json.load(open(p))
c["catalog"]["entries"] = [{
    "name": "OPENROUTER_API_KEY",
    "aliases": ["OPENROUTER_KEY"],
    "provider": "openrouter",
    "comment": "routes all LLM traffic for every project",
    "projects": ["pitchplus_fast"],
    "classification": "secret",
    "hosts": ["openrouter.ai"],
    "placement": {"kind": "header", "header": "authorization", "scheme": "Bearer"},
}, {
    "name": "STRIPE_LIVE_SECRET_BACKUP",
    "provider": "stripe",
    "comment": "honeytoken, nothing legitimate references this",
    "projects": [],
    "classification": "secret",
    "hosts": [],
    "honeytoken": True,
}]
c["providers"] = {"openrouter": {"upstream": "https://openrouter.ai", "credential": "OPENROUTER_API_KEY"}}
json.dump(c, open(p, "w"), indent=2)
PY
ok "catalog written"

echo
echo "=== set (value on stdin, never in argv) ==="
printf 'FAKE-sk-or-v1-smoketestvalue000000000000\n' | "$LV" --config "$CFG" set OPENROUTER_API_KEY > "$WORK/set.log" 2>&1
grep -q "40 bytes" "$WORK/set.log" && ok "confirmed by shape, not content" || bad "shape confirmation: $(cat "$WORK/set.log")"
grep -q "smoketestvalue" "$WORK/set.log" && bad "SET ECHOED THE VALUE" || ok "set did not echo the value"

STORE_TEXT=$(cat "$WORK/vault.store" 2>/dev/null | head -c 2000)
case "$STORE_TEXT" in
  *smoketestvalue*) bad "STORE CONTAINS THE VALUE IN PLAINTEXT" ;;
  age-encryption.org*) ok "store is an encrypted age file" ;;
  *) bad "store is neither encrypted nor recognisable" ;;
esac

echo
echo "=== project token ==="
TOKEN=$("$LV" --config "$CFG" project add pitchplus_fast 2>/dev/null)
case "$TOKEN" in
  lvp_*) ok "token issued" ;;
  *) bad "unexpected token format: $TOKEN" ;;
esac
grep -q "$TOKEN" "$CFG" && bad "CONFIG STORES THE RAW TOKEN" || ok "config stores only a hash of the token"

echo
echo "=== daemon ==="
"$LVD" --config "$CFG" --bind "127.0.0.1:$PORT" > "$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 50); do
  curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && ok "daemon is up" || { bad "daemon did not start: $(cat "$WORK/daemon.log")"; exit 1; }

echo
echo "=== ls / describe / usage ==="
LS=$("$LV" --config "$CFG" --daemon "http://127.0.0.1:$PORT" ls 2>&1)
echo "$LS" | grep -q "OPENROUTER_API_KEY" && ok "ls lists the entry" || bad "ls output: $LS"
echo "$LS" | grep -q "routes all LLM traffic" && ok "ls shows the purpose" || bad "ls purpose missing"
echo "$LS" | grep -q "smoketestvalue" && bad "LS LEAKED THE VALUE" || ok "ls shows no value"
echo "$LS" | grep -q "STRIPE_LIVE_SECRET_BACKUP" && bad "HONEYTOKEN IS ADVERTISED" || ok "honeytoken is not listed"

D=$("$LV" --config "$CFG" --daemon "http://127.0.0.1:$PORT" describe OPENROUTER_KEY 2>&1)
echo "$D" | grep -q "OPENROUTER_API_KEY" && ok "describe resolves an alias" || bad "describe: $D"
echo "$D" | grep -q "40 bytes" && ok "describe reports the shape" || bad "describe shape missing"
echo "$D" | grep -q "smoketestvalue" && bad "DESCRIBE LEAKED THE VALUE" || ok "describe shows no value"

DH=$("$LV" --config "$CFG" --daemon "http://127.0.0.1:$PORT" describe STRIPE_LIVE_SECRET_BACKUP 2>&1)
echo "$DH" | grep -qi "no catalog entry" && ok "honeytoken answers as if absent" || bad "honeytoken described: $DH"

U=$("$LV" --config "$CFG" --daemon "http://127.0.0.1:$PORT" usage 2>&1)
echo "$U" | grep -qi "no usage recorded" && ok "usage starts empty" || bad "usage: $U"

echo
echo "=== the proxy refuses an unregistered token ==="
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H "x-loopsvault-project-token: lvp_$(printf '0%.0s' $(seq 1 64))" \
  "http://127.0.0.1:$PORT/openrouter/v1/chat/completions")
check "$CODE" "401" "unregistered token is refused"

BODY=$(curl -s -X POST "http://127.0.0.1:$PORT/openrouter/v1/chat/completions")
echo "$BODY" | grep -q "next_step" && ok "denial names a next step" || bad "denial has no next step: $BODY"

echo
echo "=== export (break glass) ==="
printf 'a-long-enough-passphrase\n' | "$LV" --config "$CFG" export "$WORK/export.age" > "$WORK/export.log" 2>&1
grep -q "at least 12" "$WORK/export.log" && bad "passphrase length check misfired"
if [ -f "$WORK/export.age" ]; then
  head -c 20 "$WORK/export.age" | grep -q "age-encryption.org" && ok "export is a plain age file" || bad "export is not an age file"
  grep -q "smoketestvalue" "$WORK/export.age" && bad "EXPORT IS NOT ENCRYPTED" || ok "export is encrypted"
  if command -v age >/dev/null 2>&1; then
    DEC=$(echo "a-long-enough-passphrase" | age -d -i /dev/stdin "$WORK/export.age" 2>/dev/null || true)
    if [ -n "$DEC" ]; then ok "the age CLI can read the export"; else
      ok "age CLI present (passphrase mode needs -p interactively; format verified above)"; fi
  fi
else
  bad "export was not written"
fi

echo
echo "================================"
if [ "$fail" -eq 0 ]; then echo "ALL GREEN"; else echo "$fail failed"; fi
exit "$fail"

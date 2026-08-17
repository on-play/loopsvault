#!/bin/bash
# Install the env guard and the env-keys capability into ~/.claude/scripts/.
#
# The repo copy is the source of truth. The installed copy is a build artifact,
# so edit here and re-run this, never the other way round.
#
# Refuses to install a guard that does not pass its own suite. A guard that is
# wrong in the permissive direction leaks a credential; one that is wrong in the
# strict direction recreates the workaround loop this project exists to end.

set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
DEST="$HOME/.claude/scripts"
STAMP="$(date +%Y%m%d-%H%M%S)"

echo "Running the suite against the repo copy before touching anything installed."
if ! bash "$SRC/test-guard.sh" "$SRC/block-env-access.sh" >/tmp/env-guard-install-test.log 2>&1; then
  echo "REFUSING TO INSTALL: the suite failed." >&2
  tail -30 /tmp/env-guard-install-test.log >&2
  exit 1
fi
echo "  suite green"

mkdir -p "$DEST"

for f in block-env-access.sh env-keys.sh; do
  if [ -f "$DEST/$f" ]; then
    cp "$DEST/$f" "$DEST/$f.bak-$STAMP"
    echo "  backed up $f -> $f.bak-$STAMP"
  fi
  cp "$SRC/$f" "$DEST/$f"
  chmod +x "$DEST/$f"
  echo "  installed $f"
done

echo "Re-running the suite against the INSTALLED copy."
if ! bash "$SRC/test-guard.sh" "$DEST/block-env-access.sh" >/tmp/env-guard-installed-test.log 2>&1; then
  echo "INSTALLED COPY FAILS ITS SUITE. Rolling back." >&2
  for f in block-env-access.sh env-keys.sh; do
    [ -f "$DEST/$f.bak-$STAMP" ] && mv "$DEST/$f.bak-$STAMP" "$DEST/$f"
  done
  tail -30 /tmp/env-guard-installed-test.log >&2
  exit 1
fi
echo "  suite green against installed copy"
echo
echo "Done. The hook wiring in ~/.claude/settings.json is unchanged and already"
echo "points at $DEST/block-env-access.sh, so this takes effect on the next"
echo "tool call in every session."

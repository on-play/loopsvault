#!/bin/bash
# Collect every env variable NAME across every project, with a value fingerprint
# and never a value. Emits TSV on stdout:
#
#   project <TAB> relpath <TAB> name <TAB> len <TAB> class <TAB> kind
#
# kind is "real" or "example". Example files carry no secrets but they document
# intended names, which is useful for the catalog and useless as a leak.
#
# This is step 2 of the build order and the input to the first catalog. It reads
# other projects, which the active-project lock permits read-only, and writes
# nothing outside this repo.
#
# Usage: collect.sh [root]      default root ~/Projects

set -uo pipefail

ROOT="${1:-$HOME/Projects}"
KEYS="$(cd "$(dirname "$0")/../env-guard" && pwd)/env-keys.sh"

if [ ! -x "$KEYS" ] && [ ! -f "$KEYS" ]; then
  echo "collect.sh: cannot find env-keys.sh at $KEYS" >&2
  exit 1
fi

# Skip vendored trees. A .env inside node_modules belongs to a dependency's
# fixtures, not to the founder, and counting it would inflate every number.
find "$ROOT" \
  -name node_modules -prune -o \
  -name .git -prune -o \
  -name vendor -prune -o \
  -name .venv -prune -o \
  -name dist -prune -o \
  -name build -prune -o \
  -type f -name ".env*" -print 2>/dev/null \
| sort \
| while IFS= read -r f; do
    rel="${f#"$ROOT"/}"
    project="${rel%%/*}"
    relpath="${rel#*/}"
    [ "$relpath" = "$rel" ] && relpath="$(basename "$f")"

    base="$(basename "$f")"
    case "$base" in
      *.example|*.example.*|*.template|*.sample) kind="example" ;;
      *)                                          kind="real" ;;
    esac

    while IFS=$'\t' read -r name len class; do
      [ -z "$name" ] && continue
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$project" "$relpath" "$name" "${len#len=}" "${class#class=}" "$kind"
    done < <(bash "$KEYS" --shape "$f" 2>/dev/null)
  done

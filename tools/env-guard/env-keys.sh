#!/bin/bash
# env-keys.sh - print the variable NAMES in an env file, never the values.
#
# This is the sanctioned capability the env guard points agents at. It exists so
# an agent can answer "what variables does this project define" without any
# value entering a model context window. It is the same shape as the LoopsVault
# thesis applied to a shell script: the caller gets the answer, not the secret.
#
# Structural guarantee: this script only ever writes a captured NAME group to
# stdout. The value side of every line is matched and discarded and is never
# assigned to a variable that reaches an output statement. There is no flag that
# makes it print a value. Adding one would defeat its only purpose.
#
# Usage:
#   env-keys.sh <path> [<path>...]      names only, one per line
#   env-keys.sh --shape <path>          names plus a value fingerprint
#   env-keys.sh --count <path>          number of variables defined
#
# --shape reports the length and character class of each value so an agent can
# validate a credential's plausibility. It never emits a character of the value,
# not even a prefix, because a prefix is still part of the secret.

set -euo pipefail

MODE="names"
case "${1:-}" in
  --shape) MODE="shape"; shift ;;
  --count) MODE="count"; shift ;;
  --help|-h|"")
    grep '^#' "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
esac

if [ "$#" -eq 0 ]; then
  echo "env-keys.sh: no path given" >&2
  exit 2
fi

# Classify a value without revealing it. Returns a class name only.
classify() {
  local v="$1"
  if   [ -z "$v" ];                              then echo "empty"
  elif [[ "$v" =~ ^[0-9]+$ ]];                   then echo "digits"
  elif [[ "$v" =~ ^[0-9a-f]+$ ]];                then echo "hex-lower"
  elif [[ "$v" =~ ^[0-9A-F]+$ ]];                then echo "hex-upper"
  elif [[ "$v" =~ ^[A-Za-z0-9_-]+$ ]];           then echo "token"
  elif [[ "$v" =~ ^[A-Za-z0-9+/=]+$ ]];          then echo "base64ish"
  elif [[ "$v" =~ ^(https?|postgres|postgresql|mysql|redis|mongodb):// ]]; then echo "url"
  else                                                echo "mixed"
  fi
}

for path in "$@"; do
  if [ ! -f "$path" ]; then
    echo "env-keys.sh: not a file: $path" >&2
    continue
  fi

  count=0
  if [ "$#" -gt 1 ] && [ "$MODE" != "count" ]; then
    echo "# $path"
  fi

  while IFS= read -r line || [ -n "$line" ]; do
    # Only assignment lines matter. Comments and blanks are dropped whole.
    if [[ "$line" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      name="${BASH_REMATCH[2]}"
      count=$((count + 1))
      case "$MODE" in
        names) echo "$name" ;;
        count) : ;;
        shape)
          # The value is read here solely to measure it. It is passed to
          # classify(), which returns a class name, and to ${#raw} for a length.
          # Neither result contains any character of the value.
          raw="${BASH_REMATCH[3]}"
          raw="${raw%\"}"; raw="${raw#\"}"
          raw="${raw%\'}"; raw="${raw#\'}"
          printf '%s\tlen=%d\tclass=%s\n' "$name" "${#raw}" "$(classify "$raw")"
          ;;
      esac
    fi
  done < "$path"

  if [ "$MODE" = "count" ]; then
    if [ "$#" -gt 1 ]; then
      printf '%s\t%d\n' "$path" "$count"
    else
      echo "$count"
    fi
  fi
done

#!/bin/bash
# Block disclosure of env-file VALUES. Allow discovery of env-file PATHS and NAMES.
#
# Wired as a PreToolUse hook in ~/.claude/settings.json for
# Read|Edit|Write|NotebookEdit|Bash|Grep|Glob, so it applies to every project.
#
# Canonical source lives in the LoopsVault repo at tools/env-guard/. Edit it
# there and run tools/env-guard/install.sh. Do not hand-edit the installed copy.
#
# WHY THIS IS SHAPED THIS WAY
#
# The previous version denied any Bash command containing the literal string
# ".env". That blocked `find . -name ".env*"`, which lists paths and reveals no
# value at all, while the Glob tool was left unguarded and returns exactly the
# same paths. The line was drawn around the filename, and the filename is not
# the secret.
#
# The real boundary is the "=" sign. Everything left of it (which files exist,
# which variables they define, how long a value is) is inventory, and an agent
# needs it to be useful. Everything right of it is the secret. This guard draws
# the line there.
#
# It is an allowlist, not a blocklist: when a command touches an env path, every
# command word in it must be a known path-inspection verb. An unrecognised verb
# is denied. That way a new way to print a file is denied by default rather than
# discovered in an incident.
#
# Scope note: this guard has never covered `printenv`, `env`, or `echo $VAR`,
# because those contain no ".env" string. That gap is real and is recorded in
# the LoopsVault repo as founder/task-guard-covers-process-env.md. It is
# deliberately NOT closed here, because this change is only allowed to widen
# discovery and must not alter what is denied.

# No globbing anywhere in this script. Command strings routinely contain .env*
# and an unguarded `set --` would expand it against the real filesystem, so the
# words being classified would stop matching the words being run.
set -f

input=$(cat)
tool_name=$(echo "$input" | jq -r '.tool_name // empty')

KEYS_TOOL="$HOME/.claude/scripts/env-keys.sh"

block() {
  jq -nc --arg reason "$1" '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: $reason
    }
  }'
  exit 0
}

# Basename is .env, .env.<anything>, or .envrc
ENV_PATH_RE='(^|/)\.env(\.[a-zA-Z0-9_.-]+)?$|(^|/)\.envrc$'
# Allowed: basename is exactly .env.example
EXAMPLE_PATH_RE='(^|/)\.env\.example$'
# Literal .env or .envrc reference inside a bash command
ENV_BASH_RE='(^|[^a-zA-Z0-9_])\.env(\.[a-zA-Z0-9_-]+)?([^a-zA-Z0-9_]|$)|(^|[^a-zA-Z0-9_])\.envrc([^a-zA-Z0-9_]|$)'

# Verbs that can inspect a file's existence, location, size or line count but
# cannot emit its contents. `wc` is here on purpose: a line count is inventory.
# Note what is absent: cat, head, sort, cut, awk, sed, grep, tr and every other
# verb that writes bytes of the file to stdout.
DISCOVERY_VERBS=" find ls stat wc file test [ basename dirname realpath readlink pwd true du echo printf env-keys.sh "

# Verbs that are safe ONLY in a pipeline stage downstream of one that named an
# env path. At that point what flows through the pipe is a list of file PATHS
# that `find` or `ls` printed, so trimming or sorting that text discloses
# nothing. Absent from this list, deliberately: xargs, while, for, do, and every
# interpreter, because those take a path off stdin and open the file behind it.
STREAM_VERBS=" head tail sort uniq grep egrep fgrep rg sed awk cut tr column nl rev "

# Wrappers that run the command in their next argument. The word after one of
# these is the real command word, so `bash -c '...'` denies on `-c` rather than
# passing because it saw `bash`.
WRAPPER_VERBS=" bash sh zsh command nohup time "

# Flags whose following argument is a command to run.
EXEC_FLAGS=" -exec -execdir -ok -okdir "

next_step_hint() {
  cat <<EOF
What IS allowed, use these instead:
  find . -name ".env*" -type f      list which env files exist
  ls -la .env*                      see them with sizes and dates
  wc -l .env                        count how many variables are defined
  $KEYS_TOOL <path>          print variable NAMES, never values
  $KEYS_TOOL --shape <path>  names plus value length and character class
  .env.example                      readable in full, it holds no secrets

For what a key is FOR, ask the founder. Do not write a workaround script, and
do not try to reach the value another way. The value is the one thing off
limits; everything you need to do inventory work is in the list above.
EOF
}

# Remove heredoc BODIES before any analysis. A heredoc body is data being fed to
# a command, not a sequence of commands, so prose in it must not be parsed as
# verbs. Without this, writing a commit message or a doc that merely mentions an
# env file is denied, and the words of the sentence get reported as the
# offending commands. That is this guard's original sin in miniature: reacting
# to a string instead of to what the string does.
#
# The introducing LINE is always kept, so `cat <<EOF > .env` is still judged on
# `cat` and on its redirect.
#
# A body is only data if the thing EATING it is not an interpreter. `bash <<EOF`
# with `cat .env` inside is a real read wearing a heredoc, so the body is kept
# and classified. The default is to KEEP, and only a known data sink strips,
# because the cost of guessing wrong here is a leak rather than an annoyance.
DATA_SINKS=" git cat tee mail sendmail jq yq sqlite3 psql mysql sort uniq wc grep sed awk column less more head tail "

strip_heredocs() {
  local line delim="" in_doc=0 keep_body=0 out="" trimmed raw
  while IFS= read -r line; do
    if [ "$in_doc" -eq 1 ]; then
      trimmed="${line#"${line%%[![:space:]]*}"}"
      if [ "$trimmed" = "$delim" ]; then in_doc=0; continue; fi
      [ "$keep_body" -eq 1 ] && out+="$line"$'\n'
      continue
    fi
    if [[ "$line" =~ \<\<-?[[:space:]]*[\'\"]?([A-Za-z_][A-Za-z0-9_]*)[\'\"]? ]]; then
      delim="${BASH_REMATCH[1]}"
      in_doc=1
      # Raw first token, not first_command_word: that one sees through `bash`,
      # which is exactly the case that must NOT be treated as a data sink.
      # shellcheck disable=SC2086
      set -- $line
      raw="${1##*/}"
      if [[ "$DATA_SINKS" == *" $raw "* ]]; then keep_body=0; else keep_body=1; fi
    fi
    out+="$line"$'\n'
  done <<< "$1"
  printf '%s' "$out"
}

# Does this fragment name a real env path? .env.example is neutralised first,
# because it holds placeholders and is meant to be read.
references_env() {
  local s
  s=$(normalise_spelling "$1")
  s=$(echo "$s" | sed -E 's/(^|[^a-zA-Z0-9_])\.env\.example([^a-zA-Z0-9_]|$)/\1__ENV_EXAMPLE_OK__\2/g')
  echo "$s" | grep -qE "$ENV_BASH_RE"
}

# Collapse the spellings the shell resolves but a literal match does not.
#
# bash concatenates ."env", .e"n"v, .en''v and .en\v into the real name long
# after this guard has looked at the text. The guard sees a spelling; the kernel
# opens the file. Found by the jainyagi.com session on 2026-08-19, reproduced
# here, and every one of those forms reads the file if it runs.
#
# Runs ONLY on the copy used to decide whether a path is referenced, never on
# the copy used to identify verbs. Stripping quotes from a command would merge
# separate words and produce exactly the misattributed denial this guard is
# already criticised for.
#
# It can only make MORE text match, so it tightens and cannot widen. That is why
# it needs no both-directions redesign, unlike an operand-aware rule would.
#
# Deliberately NOT closed, and recorded in founder/task-guard-data-vs-path.md
# rather than half-attempted: a path held in a variable (F=<name>; cat $F) and
# one produced by a substitution (cat "$(echo <name>)"). Both need the guard to
# track values through the shell, which is a tail with no end. String matching
# has a ceiling; the kernel boundary in task-service-account.md is the way past
# it.
normalise_spelling() {
  local s="$1"
  case "$s" in
    *'\x'*)
      # Hex escapes, decoded before the quotes go. Only the characters that
      # spell the guarded names, so this stays a targeted collapse rather than a
      # general unescaper.
      s=$(printf '%s' "$s" | sed -E 's/\\x2[eE]/./g; s/\\x65/e/g; s/\\x6[eE]/n/g; s/\\x76/v/g; s/\\x72/r/g; s/\\x63/c/g')
      ;;
  esac
  s="${s//\"/}"
  s="${s//\'/}"
  s="${s//\\/}"
  printf '%s' "$s"
}

# The verb of a single segment: skip VAR=value prefixes, skip bare backslashes
# left behind by `\;`, and see through transparent wrappers like `bash -c`.
first_command_word() {
  # shellcheck disable=SC2086
  set -- $1
  while [ "$#" -gt 0 ]; do
    [ -z "$1" ] && { shift; continue; }
    # A bare backslash is what `\;` leaves once `;` has split the segment. It is
    # punctuation, not a verb. Only an all-backslash token is skipped: `\cat`
    # keeps its backslash, stays out of the allowlist, and is still denied.
    if [[ "$1" =~ ^\\+$ ]]; then shift; continue; fi
    case "$1" in
      *=*) shift ;;                    # leading assignment prefix, e.g. FOO=bar cmd
      *)
        if [[ "$WRAPPER_VERBS" == *" ${1##*/} "* ]]; then shift; continue; fi
        printf '%s' "${1##*/}"
        return ;;
    esac
  done
}

# Every verb that could reach an env path, across statements, pipelines,
# substitutions, and find -exec clauses. Prints one offending verb per line.
#
# Judging verbs globally is what made the original guard useless: it saw `.env`
# anywhere in the string and refused, even when the verb was `find`, which
# cannot print a file. Position is what separates
#
#   cat .env | head                  the dangerous verb HOLDS the env file
#   find . -name ".env*" | head      head is trimming a list of paths
#
# and position matters in two directions. A stage that NAMES an env path must
# use a verb that cannot open it. A stage DOWNSTREAM of one that named an env
# path is receiving those paths on stdin, so it may only use a verb that treats
# them as text. That second rule is what stops `... | xargs cat` and
# `... | while read f; do cat $f; done`.
#
# Downstream-ness resets at each statement boundary. Without the reset,
# `ls .env* && cat README.md` would deny on an unrelated file in a later
# statement, which is the same over-blocking wearing a new costume.
bash_offenders() {
  local cmd="$1" ch stmt stage seen w stages

  # Split into statements at every construct that starts an independent command.
  # `(` and backtick are in this set, so the body of $(...) and `...` becomes
  # its own statement and is judged on its own merits. Without that,
  # `echo $(cat .env)` would be judged on `echo` alone and would pass.
  #
  # Done with parameter expansion rather than tr on purpose: building the
  # replacement with $(printf '\n...') silently yields an EMPTY string, because
  # command substitution strips trailing newlines. tr then fails with "empty
  # string2" and passes every command through unsplit. Every deny test catches
  # that, but it is exactly the kind of thing that looks correct in review.
  #
  # `<` and `>` are deliberately NOT split on. A redirect target is a filename,
  # not a command, and splitting there made `ls -1 .env* 2>/dev/null` deny on a
  # phantom command word of "null". Redirects get their own check below, which
  # is what actually catches `ls > .env`.
  local statements="$cmd"
  for ch in '`' ';' '&' '(' ')' '{' '}'; do
    statements="${statements//"$ch"/$'\n'}"
  done

  while IFS= read -r stmt; do
    [ -z "$stmt" ] && continue
    seen=0
    stages="${stmt//|/$'\n'}"
    while IFS= read -r stage; do
      [ -z "$stage" ] && continue
      w=$(first_command_word "$stage")
      [ -z "$w" ] && continue
      if references_env "$stage"; then
        seen=1
        [[ "$DISCOVERY_VERBS" == *" $w "* ]] || printf '%s\n' "$w"
      elif [ "$seen" -eq 1 ]; then
        if [[ "$DISCOVERY_VERBS" != *" $w "* ]] && [[ "$STREAM_VERBS" != *" $w "* ]]; then
          printf '%s\n' "$w"
        fi
      fi
    done <<< "$stages"
  done <<< "$statements"

  # Any command introduced by -exec / -execdir / -ok / -okdir, or by xargs.
  # These sit mid-stage, so the first-word pass above cannot see them, and they
  # receive env paths as arguments, so the strict list applies rather than the
  # stream list.
  # shellcheck disable=SC2086
  set -- $cmd
  local take_next=0
  while [ "$#" -gt 0 ]; do
    if [ "$take_next" -eq 1 ]; then
      case "$1" in
        -*) : ;;                       # xargs flag, keep looking
        *)
          [[ "$DISCOVERY_VERBS" == *" ${1##*/} "* ]] || printf '%s\n' "${1##*/}"
          take_next=0 ;;
      esac
    elif [[ "$EXEC_FLAGS" == *" $1 "* ]]; then
      take_next=1
    elif [ "${1##*/}" = "xargs" ]; then
      take_next=1
    fi
    shift
  done
}

# Deny shell redirection that WRITES into an env file. The verb allowlist cannot
# catch this on its own: in `ls > .env` the verb is `ls`, which is a legitimate
# discovery verb, and the damage is done by the redirect. Truncating an env file
# destroys credentials that may exist nowhere else on the machine.
redirect_writes_env() {
  local cmd="$1" tok rest expect_target=0
  # shellcheck disable=SC2086
  set -- $cmd
  while [ "$#" -gt 0 ]; do
    tok="$1"
    if [ "$expect_target" -eq 1 ]; then
      expect_target=0
      if echo "$tok" | grep -qE "$ENV_PATH_RE" && ! echo "$tok" | grep -qE "$EXAMPLE_PATH_RE"; then
        return 0
      fi
    elif [[ "$tok" =~ ^[0-9]*(\&?\>\>?)(.*)$ ]]; then
      rest="${BASH_REMATCH[2]}"
      if [ -z "$rest" ]; then
        expect_target=1
      elif echo "$rest" | grep -qE "$ENV_PATH_RE" && ! echo "$rest" | grep -qE "$EXAMPLE_PATH_RE"; then
        return 0
      fi
    fi
    shift
  done
  return 1
}

case "$tool_name" in
  Read)
    file_path=$(echo "$input" | jq -r '.tool_input.file_path // empty')
    if echo "$file_path" | grep -qE "$ENV_PATH_RE" && ! echo "$file_path" | grep -qE "$EXAMPLE_PATH_RE"; then
      block "Reading $file_path is blocked: it would pull every value in that file into your context window, which is uploaded to a model API and stored in a transcript. That is the exact leak this guard exists to stop.

$(next_step_hint)"
    fi
    ;;

  Edit|Write|NotebookEdit)
    file_path=$(echo "$input" | jq -r '.tool_input.file_path // empty')
    if echo "$file_path" | grep -qE "$ENV_PATH_RE" && ! echo "$file_path" | grep -qE "$EXAMPLE_PATH_RE"; then
      block "Editing $file_path is blocked: Edit requires reading the file first, so it discloses values, and a bad write can destroy credentials that exist nowhere else.

To add or change a variable, tell the founder the exact line to add and let them paste it. To document it for other agents, edit .env.example instead, which is allowed and is where the placeholder belongs.

$(next_step_hint)"
    fi
    ;;

  Bash)
    command=$(echo "$input" | jq -r '.tool_input.command // empty')
    # Heredoc bodies are data. Drop them before anything is classified.
    command=$(strip_heredocs "$command")
    # Normalise the spelling first, or a quoted form never reaches the per-stage
    # logic below at all. Then neutralise the example file, then look.
    stripped=$(normalise_spelling "$command")
    stripped=$(echo "$stripped" | sed -E 's/(^|[^a-zA-Z0-9_])\.env\.example([^a-zA-Z0-9_]|$)/\1__ENV_EXAMPLE_OK__\2/g')
    if echo "$stripped" | grep -qE "$ENV_BASH_RE"; then
      # The command touches a real env path. Two ways it can do harm: a verb
      # that prints the contents, or a redirect that overwrites the file.
      if redirect_writes_env "$command"; then
        block "Blocked: this command redirects output INTO an env file, which truncates it. Credentials in that file may exist nowhere else on this machine, and there is no undo.

To change a variable, tell the founder the exact line and let them paste it. To document one, write to .env.example instead.

$(next_step_hint)"
      fi

      # Every verb that can reach the env path must be one that cannot open it.
      offenders=""
      while IFS= read -r word; do
        [ -z "$word" ] && continue
        case " $offenders " in *" $word "*) continue ;; esac
        offenders="$offenders $word"
      done < <(bash_offenders "$command")

      if [ -n "$offenders" ]; then
        block "Blocked: this command reaches an env file using$offenders, which can write the file's contents to stdout and therefore into your context window.

Path and name discovery are allowed. Only the values are off limits.

$(next_step_hint)"
      fi
    fi
    ;;

  Grep)
    path=$(echo "$input" | jq -r '.tool_input.path // empty')
    glob=$(echo "$input" | jq -r '.tool_input.glob // empty')
    combined="${path}|${glob}"
    stripped=$(echo "$combined" | sed -E 's/\.env\.example/__ENV_EXAMPLE_OK__/g')
    if echo "$stripped" | grep -qE '\.env'; then
      block "Grep on env paths is blocked: it prints matching lines, and in an env file the matching line is the secret. Even a match count leaks, because it confirms a guessed value.

$(next_step_hint)"
    fi
    ;;

  Glob)
    # Deliberately allowed. Glob returns paths and nothing else, which is the
    # same information `find` gives and is inventory, not disclosure. Recorded
    # here so nobody "fixes" this by adding a block that would contradict the
    # Bash rules above.
    :
    ;;
esac

exit 0

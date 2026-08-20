#!/bin/zsh
set -u

usage() {
  print -u2 "usage: run-codex-bounded.sh <read-only|workspace-write> <repo> <prompt-file> <evidence-dir>"
  exit 64
}

[[ $# -eq 4 ]] || usage
MODE="$1"
REPO="${2:A}"
PROMPT_FILE="${3:A}"
EVIDENCE="${4:A}"
CODEX="/Users/marcagent/.local/bin/codex"

[[ "$MODE" == "read-only" || "$MODE" == "workspace-write" ]] || usage
[[ -d "$REPO/.git" || -f "$REPO/.git" ]] || { print -u2 "Refusing non-Git workspace: $REPO"; exit 65; }
[[ -f "$PROMPT_FILE" ]] || { print -u2 "Prompt file missing: $PROMPT_FILE"; exit 66; }
[[ -x "$CODEX" ]] || { print -u2 "Stable Codex wrapper missing: $CODEX"; exit 67; }

case "$REPO" in
  "$HOME/.hermes"*|"$HOME/.codex"*|"$HOME/MuzologyAI/data"*|*"/sessions"*|*"request_dump"*)
    print -u2 "Refusing sensitive workspace: $REPO"
    exit 68
    ;;
esac

mkdir -p "$EVIDENCE"
chmod 700 "$EVIDENCE"

"$CODEX" --version > "$EVIDENCE/version.txt" 2>&1
{
  print "repo=$REPO"
  print "mode=$MODE"
  print "approval=never"
  print "ephemeral=true"
  print "prompt_file=$PROMPT_FILE"
} > "$EVIDENCE/command.txt"

git -C "$REPO" status --short --branch > "$EVIDENCE/git-before.txt"

"$CODEX" \
  -C "$REPO" \
  --sandbox "$MODE" \
  --ask-for-approval never \
  exec --ephemeral --json \
  --output-last-message "$EVIDENCE/final.md" \
  - < "$PROMPT_FILE" \
  > "$EVIDENCE/events.jsonl" \
  2> "$EVIDENCE/stderr.log"
RC=$?

git -C "$REPO" status --short --branch > "$EVIDENCE/git-after.txt"
git -C "$REPO" diff --binary HEAD > "$EVIDENCE/diff.patch"
git -C "$REPO" ls-files --others --exclude-standard > "$EVIDENCE/untracked.txt"
while IFS= read -r file; do
  [[ -n "$file" ]] || continue
  git diff --binary --no-index /dev/null "$REPO/$file" >> "$EVIDENCE/diff.patch" 2>/dev/null || true
done < "$EVIDENCE/untracked.txt"

python3 - "$EVIDENCE" "$RC" <<'PY'
import json, pathlib, sys
root=pathlib.Path(sys.argv[1]); rc=int(sys.argv[2])
failed=[]; count=0
p=root/'events.jsonl'
if p.exists():
    for line in p.read_text(errors='replace').splitlines():
        if not line.strip(): continue
        try: event=json.loads(line)
        except Exception:
            failed.append('invalid_jsonl'); continue
        count += 1
        if event.get('type') in {'turn.failed','error'}:
            failed.append(event.get('type'))
result={
    'exit_code': rc,
    'event_count': count,
    'failed_event_types': sorted(set(failed)),
    'final_message_exists': (root/'final.md').exists(),
    'diff_bytes': (root/'diff.patch').stat().st_size if (root/'diff.patch').exists() else 0,
}
(root/'result.json').write_text(json.dumps(result, indent=2)+'\n')
PY

exit "$RC"

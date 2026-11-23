#!/usr/bin/env bash
# Run every attack and failure scenario (backend/tests/security) and print a
# results table: scenario -> attempt -> mechanism -> observed result ->
# observed audit record -> outcome.
#
#   scripts/attacks/run_all.sh                 # starts the emulators if needed (stops them again after)
#   scripts/attacks/run_all.sh --no-emulators  # in-memory scenarios only; emulator scenarios SKIP with a reason
#   scripts/attacks/run_all.sh --markdown      # also print the table as markdown
#
# Exit status is pytest's. An XFAIL row would be a known, unfixed finding written as a
# strict xfail test; since the Phase 8 fixes (F1-F6) there are none.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BACKEND="$REPO_DIR/backend"
PY="$BACKEND/.venv/bin/python"
EMU="$REPO_DIR/scripts/emulators.sh"

USE_EMU=1
MARKDOWN=0
for a in "$@"; do
  case "$a" in
    --no-emulators) USE_EMU=0 ;;
    --markdown) MARKDOWN=1 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

[ -x "$PY" ] || { echo "backend venv not found at $PY" >&2; exit 1; }

WORK="$(mktemp -d)"
STARTED=()
cleanup() {
  for n in "${STARTED[@]:-}"; do
    [ -n "$n" ] && "$EMU" stop-one "$n" >/dev/null 2>&1
  done
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

if [ "$USE_EMU" = 1 ]; then
  status="$("$EMU" status)"
  for n in s3 azure gcs; do
    if ! grep -q "^\[$n\] running" <<<"$status"; then
      "$EMU" start-one "$n" >/dev/null || echo "warning: could not start emulator $n; its scenarios will SKIP" >&2
      STARTED+=("$n")
    fi
  done
fi

echo "== Running backend/tests/security =="
cd "$BACKEND"
ZT_SECURITY_EVIDENCE="$WORK/evidence.json" "$PY" -m pytest tests/security -q -rs -rx -p no:cacheprovider \
  2>&1 | grep -v -E '^\{"ts"|^(INFO|WARNING|ERROR) +zt\.' | tee "$WORK/pytest.txt"
rc=${PIPESTATUS[0]}

echo
echo "== Attack / failure scenario results =="
"$PY" "$SCRIPT_DIR/report.py" "$WORK/evidence.json"
if [ "$MARKDOWN" = 1 ]; then
  echo
  "$PY" "$SCRIPT_DIR/report.py" "$WORK/evidence.json" --markdown
fi
echo
grep -E '^[0-9]+ (passed|failed)|passed|failed' "$WORK/pytest.txt" | tail -n 1
exit "$rc"

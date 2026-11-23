#!/usr/bin/env bash
# End-to-end security demonstration (16 numbered steps) against the REAL
# backend server over HTTP and the REAL local storage emulators.
#
#   scripts/demo.sh                 # prints the demonstration
#   scripts/demo.sh | tee out.txt   # keep a transcript (no tokens/passwords are ever printed)
#
# What it does:
#   * starts the three emulators (scripts/emulators.sh) unless already running,
#   * starts the backend with scripts/run-dev.sh in the background on
#     127.0.0.1:${ZT_DEMO_PORT:-8765} with a TEMPORARY data dir and a bootstrap
#     admin whose password is generated for this run and never printed,
#   * runs scripts/demo/demo.py (httpx + boto3 / azure-storage-blob /
#     google-cloud-storage + sqlite3),
#   * on exit (trap): stops the server, restarts the GCS emulator if the demo
#     left it stopped, stops the emulators the demo itself started, and deletes
#     the temporary data dir.
# The server runs with the default policy require_mfa_for_login=true: the
# demo enrols TOTP for every account (pyotp) within the self-enrolment window
# and signs in again with a code (ADR-0010).
# The demo uses its OWN per-run buckets (zt-demo-<random>) so it never touches
# another deployment's objects (audit anchors are additionally namespaced per
# audit log since the F4 fix); it empties them on exit and rewrites
# scripts/.emulators/run/emulators.env back to the default bucket.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKEND="$REPO_DIR/backend"
PY="$BACKEND/.venv/bin/python"
EMU="$SCRIPT_DIR/emulators.sh"
PORT="${ZT_DEMO_PORT:-8765}"
HOST="127.0.0.1"

[ -x "$PY" ] || { echo "backend venv not found at $PY" >&2; exit 1; }
if (exec 3<>"/dev/tcp/$HOST/$PORT") 2>/dev/null; then
  echo "port $PORT is already in use; set ZT_DEMO_PORT to a free port" >&2
  exit 1
fi

DATA_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zt-demo.XXXXXX")"
SERVER_LOG="$DATA_DIR/server.log"
SERVER_PID=""
STARTED_EMU=()
status_before="$("$EMU" status)"
for n in s3 azure gcs; do
  grep -q "^\[$n\] running" <<<"$status_before" || STARTED_EMU+=("$n")
done

cleanup() {
  local rc=$?
  set +e
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM -- "-$SERVER_PID" 2>/dev/null || kill -TERM "$SERVER_PID" 2>/dev/null
    for _ in $(seq 1 50); do kill -0 "$SERVER_PID" 2>/dev/null || break; sleep 0.1; done
    kill -KILL -- "-$SERVER_PID" 2>/dev/null
  fi
  # the demo stops GCS in step 13; make sure it is back (needed to empty the demo bucket)
  "$EMU" status | grep -q "^\[gcs\] running" || "$EMU" start-one gcs >/dev/null 2>&1
  if [ -n "${ZT_EMU_BUCKET:-}" ]; then
    ( source "$SCRIPT_DIR/.emulators/run/emulators.env" 2>/dev/null
      [ "${ZT_S3_BUCKET:-}" = "$ZT_EMU_BUCKET" ] && "$PY" "$SCRIPT_DIR/demo/demo.py" --wipe-buckets )
    ( unset ZT_EMU_BUCKET; "$EMU" start >/dev/null 2>&1 )      # env file back to the default bucket
  fi
  for n in "${STARTED_EMU[@]:-}"; do
    [ -n "$n" ] && "$EMU" stop-one "$n" >/dev/null 2>&1
  done
  if [ "$rc" -ne 0 ] && [ -f "$SERVER_LOG" ]; then
    echo "--- last server log lines (secrets are redacted by the app logger) ---" >&2
    tail -n 20 "$SERVER_LOG" >&2
  fi
  rm -rf "$DATA_DIR"
  echo
  echo "[demo] cleaned up: server stopped, emulators restored (${STARTED_EMU[*]:-none} stopped), temp data removed"
  exit "$rc"
}
trap cleanup EXIT INT TERM

export ZT_EMU_BUCKET="zt-demo-$("$PY" -c 'import secrets; print(secrets.token_hex(5))')"
echo "[demo] starting emulators (per-run buckets: $ZT_EMU_BUCKET)"
"$EMU" start >/dev/null
# shellcheck disable=SC1091
source "$SCRIPT_DIR/.emulators/run/emulators.env"

ADMIN_USER="demo-admin"
ADMIN_PASSWORD="$("$PY" -c 'import secrets; print("Adm-" + secrets.token_urlsafe(18))')"

echo "[demo] starting backend on http://$HOST:$PORT (data dir: temporary)"
(
  export ZT_DATA_DIR="$DATA_DIR/server" ZT_DEV_HOST="$HOST" ZT_DEV_PORT="$PORT" ZT_ENV=development \
         ZT_BOOTSTRAP_ADMIN_USERNAME="$ADMIN_USER" ZT_BOOTSTRAP_ADMIN_PASSWORD="$ADMIN_PASSWORD" \
         ZT_ENABLE_FAULT_INJECTION=false ZT_HEALTH_CHECK_INTERVAL_SECONDS=2 ZT_LOG_LEVEL=WARNING \
         ZT_AUDIT_CHECKPOINT_EVERY=25
  exec setsid "$SCRIPT_DIR/run-dev.sh"
) >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 150); do
  if "$PY" -c "import httpx,sys; sys.exit(0 if httpx.get('http://$HOST:$PORT/api/health', timeout=1).status_code == 200 else 1)" 2>/dev/null; then
    break
  fi
  kill -0 "$SERVER_PID" 2>/dev/null || { echo "[demo] server exited during startup" >&2; exit 1; }
  sleep 0.2
done

ZT_DEMO_URL="http://$HOST:$PORT" ZT_DEMO_DATA_DIR="$DATA_DIR/server" ZT_DEMO_ADMIN_USER="$ADMIN_USER" \
ZT_DEMO_ADMIN_PASSWORD="$ADMIN_PASSWORD" ZT_DEMO_EMULATORS_SH="$EMU" \
  "$PY" "$SCRIPT_DIR/demo/demo.py"

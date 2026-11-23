#!/usr/bin/env bash
# Local development server.
#
#   scripts/run-dev.sh
#
# 1. starts the three storage EMULATORS (scripts/emulators.sh start) and loads
#    their ZT_* endpoint variables;
# 2. generates a development KMS root key into the data dir if none is
#    configured (0600; development only: it sits next to the keystore);
# 3. runs uvicorn on 127.0.0.1:8000 (plain http, so ZT_COOKIE_SECURE=false);
# 4. creates a bootstrap admin at startup if ZT_BOOTSTRAP_ADMIN_USERNAME and
#    ZT_BOOTSTRAP_ADMIN_PASSWORD are set in the environment (or backend/.env).
#
# Ctrl-C stops the server; the emulators keep running (scripts/emulators.sh stop).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKEND="$REPO_DIR/backend"
VENV_BIN="$BACKEND/.venv/bin"

"$SCRIPT_DIR/emulators.sh" start
# shellcheck disable=SC1091
source "$SCRIPT_DIR/.emulators/run/emulators.env"

export ZT_ENV="${ZT_ENV:-development}"
export ZT_DATA_DIR="${ZT_DATA_DIR:-$BACKEND/data}"
export ZT_COOKIE_SECURE="${ZT_COOKIE_SECURE:-false}"
export ZT_ENABLE_FAULT_INJECTION="${ZT_ENABLE_FAULT_INJECTION:-true}"
HOST="${ZT_DEV_HOST:-127.0.0.1}"
PORT="${ZT_DEV_PORT:-8000}"

if [[ "$ZT_ENV" == "production" ]]; then
  echo "run-dev.sh is for development only (ZT_ENV=production refused)" >&2
  exit 1
fi

mkdir -p "$ZT_DATA_DIR/kms"
chmod 700 "$ZT_DATA_DIR" "$ZT_DATA_DIR/kms"
if [[ -z "${ZT_KMS_ROOT_KEY:-}" && -z "${ZT_KMS_ROOT_KEY_FILE:-}" ]]; then
  KEY_FILE="$ZT_DATA_DIR/kms/dev-root-key.b64"
  if [[ ! -s "$KEY_FILE" ]]; then
    ( umask 077; "$VENV_BIN/python" -c 'import base64, os; print(base64.b64encode(os.urandom(32)).decode())' > "$KEY_FILE" )
    echo "generated development KMS root key: $KEY_FILE (development only)"
  fi
  export ZT_KMS_ROOT_KEY_FILE="$KEY_FILE"
fi

if [[ -n "${ZT_BOOTSTRAP_ADMIN_USERNAME:-}" && -n "${ZT_BOOTSTRAP_ADMIN_PASSWORD:-}" ]]; then
  echo "bootstrap admin '${ZT_BOOTSTRAP_ADMIN_USERNAME}' will be created at startup if absent"
fi

cd "$BACKEND"
echo "API: http://$HOST:$PORT  (docs: http://$HOST:$PORT/docs)"
exec "$VENV_BIN/uvicorn" app.main:app --host "$HOST" --port "$PORT" --no-access-log --log-level info

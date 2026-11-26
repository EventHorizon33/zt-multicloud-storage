#!/usr/bin/env bash
# Local storage emulators for development, tests and outage demonstrations.
#
#   scripts/emulators.sh start | stop | status | reset
#   scripts/emulators.sh start-one <s3|azure|gcs>
#   scripts/emulators.sh stop-one  <s3|azure|gcs>
#
# Starts three INDEPENDENT local processes (no Docker needed):
#   s3     moto server            http://127.0.0.1:5001   (in-memory: data is lost on stop)
#   azure  Azurite blob service   http://127.0.0.1:10000  (data under scripts/.emulators/data/azurite)
#   gcs    gcp-storage-emulator   http://127.0.0.1:9023   (data under scripts/.emulators/data/gcs)
#
# These are EMULATORS. They let the real boto3 / azure-storage-blob /
# google-cloud-storage SDKs run locally; they are not AWS, Azure or GCP.
#
# Pid files and logs live in scripts/.emulators/run/. `stop` only kills pids
# recorded there (and only if the pid still belongs to the emulator command).
# Safe to run repeatedly and from any working directory.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
EMU_DIR="$SCRIPT_DIR/.emulators"
RUN_DIR="$EMU_DIR/run"
DATA_DIR="${ZT_EMU_DATA_DIR:-$EMU_DIR/data}"   # override: the statistical analysis starts every experiment on an empty data directory
VENV_BIN="$REPO_DIR/backend/.venv/bin"
PY="$VENV_BIN/python"
ENV_FILE="$RUN_DIR/emulators.env"

HOST="127.0.0.1"
S3_PORT="${ZT_EMU_S3_PORT:-5001}"
AZURE_PORT="${ZT_EMU_AZURE_PORT:-10000}"
GCS_PORT="${ZT_EMU_GCS_PORT:-9023}"
BUCKET="${ZT_EMU_BUCKET:-zt-chunks}"

# Azurite's well-known development account. This name/key pair is a PUBLIC
# constant documented by Microsoft for the storage emulator
# (https://learn.microsoft.com/azure/storage/common/storage-use-azurite); it is
# identical on every machine, grants access to nothing but a local Azurite
# process, and is therefore NOT a secret.
AZURITE_ACCOUNT="devstoreaccount1"
AZURITE_KEY="Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
AZURITE_CONN="DefaultEndpointsProtocol=http;AccountName=${AZURITE_ACCOUNT};AccountKey=${AZURITE_KEY};BlobEndpoint=http://${HOST}:${AZURE_PORT}/${AZURITE_ACCOUNT};"

mkdir -p "$RUN_DIR" "$DATA_DIR"

port_of() {
  case "$1" in
    s3) echo "$S3_PORT" ;; azure) echo "$AZURE_PORT" ;; gcs) echo "$GCS_PORT" ;;
    *) echo "unknown emulator: $1 (expected s3|azure|gcs)" >&2; return 2 ;;
  esac
}

# marker that must appear in the process command line for a pid to be "ours"
marker_of() {
  case "$1" in
    s3) echo "moto" ;; azure) echo "azurite" ;; gcs) echo "gcp-storage-emulator" ;;
  esac
}

pid_file() { echo "$RUN_DIR/$1.pid"; }
log_file() { echo "$RUN_DIR/$1.log"; }

# prints the pid if the recorded process is alive and is still our emulator
live_pid() {
  local f pid cmd
  f="$(pid_file "$1")"
  [ -f "$f" ] || return 1
  pid="$(cat "$f" 2>/dev/null)"
  [ -n "$pid" ] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || ps -p "$pid" -o args= 2>/dev/null)"
  case "$cmd" in
    *"$(marker_of "$1")"*) echo "$pid"; return 0 ;;
  esac
  return 1
}

port_open() {
  (exec 3<>"/dev/tcp/$HOST/$1") 2>/dev/null
}

wait_port() {  # name port seconds
  local i=0 max=$(( $3 * 5 ))
  while [ "$i" -lt "$max" ]; do
    port_open "$2" && return 0
    live_pid "$1" >/dev/null || return 1   # process died
    sleep 0.2
    i=$((i + 1))
  done
  return 1
}

launch() {  # name -- command...
  local name="$1"; shift
  local log; log="$(log_file "$name")"
  # setsid: own session, so the emulator survives the calling shell and a
  # `kill` of the recorded pid cannot hit anything else.
  if command -v setsid >/dev/null 2>&1; then
    setsid nohup "$@" >>"$log" 2>&1 </dev/null &
  else
    nohup "$@" >>"$log" 2>&1 </dev/null &
  fi
  echo $! > "$(pid_file "$name")"
}

start_one() {
  local name="$1" port pid
  port="$(port_of "$name")" || return 2
  if pid="$(live_pid "$name")"; then
    echo "[$name] already running (pid $pid, port $port)"
  else
    rm -f "$(pid_file "$name")"
    if port_open "$port"; then
      echo "[$name] ERROR: port $port is already in use by a process this script did not start" >&2
      return 1
    fi
    : > "$(log_file "$name")"
    case "$name" in
      s3)
        [ -x "$VENV_BIN/moto_server" ] || { echo "[s3] ERROR: $VENV_BIN/moto_server not found" >&2; return 1; }
        launch s3 "$VENV_BIN/moto_server" -H "$HOST" -p "$port"
        ;;
      azure)
        local az="$EMU_DIR/node_modules/.bin/azurite-blob"
        [ -x "$az" ] || { echo "[azure] ERROR: $az not found (npm install azurite in scripts/.emulators)" >&2; return 1; }
        mkdir -p "$DATA_DIR/azurite"
        launch azure "$az" --blobHost "$HOST" --blobPort "$port" --location "$DATA_DIR/azurite" \
          --skipApiVersionCheck --disableTelemetry --silent
        ;;
      gcs)
        [ -x "$VENV_BIN/gcp-storage-emulator" ] || { echo "[gcs] ERROR: $VENV_BIN/gcp-storage-emulator not found" >&2; return 1; }
        mkdir -p "$DATA_DIR/gcs"
        launch gcs "$VENV_BIN/gcp-storage-emulator" --data-dir "$DATA_DIR/gcs" start --host "$HOST" --port "$port"
        ;;
    esac
    if ! wait_port "$name" "$port" 40; then
      echo "[$name] ERROR: did not start listening on $HOST:$port; last log lines:" >&2
      tail -n 15 "$(log_file "$name")" >&2
      stop_one "$name" >/dev/null 2>&1
      return 1
    fi
    echo "[$name] started (pid $(cat "$(pid_file "$name")"), port $port, log $(log_file "$name"))"
  fi
  write_env
  ensure_buckets "$name"
}

stop_one() {
  local name="$1" pid i
  port_of "$name" >/dev/null || return 2
  if pid="$(live_pid "$name")"; then
    kill "$pid" 2>/dev/null
    i=0
    while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
    if kill -0 "$pid" 2>/dev/null; then kill -9 "$pid" 2>/dev/null; sleep 0.2; fi
    echo "[$name] stopped (pid $pid)"
  else
    echo "[$name] not running"
  fi
  rm -f "$(pid_file "$name")"
}

status_one() {
  local name="$1" port pid
  port="$(port_of "$name")"
  if pid="$(live_pid "$name")"; then
    if port_open "$port"; then echo "[$name] running   pid $pid  http://$HOST:$port"
    else echo "[$name] starting  pid $pid  (port $port not answering yet)"; fi
  else
    if port_open "$port"; then echo "[$name] NOT MANAGED: port $port answers but was not started by this script"
    else echo "[$name] stopped"; fi
  fi
}

write_env() {
  cat > "$ENV_FILE" <<ENVEOF
# Generated by scripts/emulators.sh. Local EMULATOR endpoints only.
# S3 credentials are dummy values accepted by moto. The Azurite account key is
# Microsoft's public, documented development constant (not a secret).
export ZT_STORAGE_PROVIDERS="aws-s3,azure-blob,gcs"
export ZT_S3_ENDPOINT_URL="http://${HOST}:${S3_PORT}"
export ZT_S3_REGION="us-east-1"
export ZT_S3_BUCKET="${BUCKET}"
export ZT_S3_ACCESS_KEY_ID="test"
export ZT_S3_SECRET_ACCESS_KEY="test"
export ZT_AZURE_CONNECTION_STRING="${AZURITE_CONN}"
export ZT_AZURE_CONTAINER="${BUCKET}"
export ZT_GCS_ENDPOINT_URL="http://${HOST}:${GCS_PORT}"
export ZT_GCS_PROJECT="zt-local"
export ZT_GCS_BUCKET="${BUCKET}"
ENVEOF
}

ensure_buckets() {  # [name...]; creates the bucket/container through the app's own adapters
  ( set -a; . "$ENV_FILE"; set +a; "$PY" "$SCRIPT_DIR/emulators/ensure_buckets.py" "$@" )
}

print_env() {
  echo
  echo "Environment for the backend (also written to $ENV_FILE):"
  echo "  source $ENV_FILE"
  echo
  cat "$ENV_FILE"
}

cmd="${1:-}"
case "$cmd" in
  start)
    rc=0
    for n in s3 azure gcs; do start_one "$n" || rc=1; done
    print_env
    exit "$rc"
    ;;
  stop)
    for n in s3 azure gcs; do stop_one "$n"; done
    ;;
  status)
    for n in s3 azure gcs; do status_one "$n"; done
    ;;
  reset)
    for n in s3 azure gcs; do stop_one "$n"; done
    rm -rf "$DATA_DIR/azurite" "$DATA_DIR/gcs"
    echo "[reset] emulator data wiped"
    rc=0
    for n in s3 azure gcs; do start_one "$n" || rc=1; done
    print_env
    exit "$rc"
    ;;
  start-one)
    [ $# -eq 2 ] || { echo "usage: $0 start-one <s3|azure|gcs>" >&2; exit 2; }
    start_one "$2"
    ;;
  stop-one)
    [ $# -eq 2 ] || { echo "usage: $0 stop-one <s3|azure|gcs>" >&2; exit 2; }
    stop_one "$2"
    ;;
  *)
    echo "usage: $0 {start|stop|status|reset|start-one <s3|azure|gcs>|stop-one <s3|azure|gcs>}" >&2
    exit 2
    ;;
esac

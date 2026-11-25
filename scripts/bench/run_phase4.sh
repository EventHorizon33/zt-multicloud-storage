#!/usr/bin/env bash
# Phase 4: real-cloud benchmark with the chosen configuration (the "Full" plan).
#
#   scripts/bench/run_phase4.sh              interactive run against REAL S3, Azure Blob and GCS
#   scripts/bench/run_phase4.sh --dry-run    show the plan and the configuration, contact nothing, ask nothing
#   scripts/bench/run_phase4.sh --rehearsal  the same flow on local emulators with tiny sizes (free, no prompts)
#
# Configuration (why: docs in Phase4_Run_Sheet.docx):
#   sizes 10, 40, 100 and 1024 MiB; backend chunk sizes 1 MiB (framework default) and 16 MiB (deployment setting);
#   5 repeats (3 at 1 GiB); a direct single-object baseline to each provider; byte cap 65 GiB.
#
# Secrets are asked for with no echo, kept only in this process, and never written to disk or to the results.
# Run it on a VM in the same region as the buckets (recommended), or on your own machine; label the run.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../backend"
PY=.venv/bin/python
RC=../scripts/bench/realcloud.py
MODE=real
case "${1:-}" in
  --dry-run) MODE=dry ;;
  --rehearsal) MODE=rehearsal ;;
  "") ;;
  *) echo "usage: $0 [--dry-run|--rehearsal]" >&2; exit 2 ;;
esac

SIZES="10,40,100,1024"; CHUNKS="1,16"; REPS=5; REPS_LARGE=3; CAP=65; BASE_MAX=1024
TARGET=real
if [ "$MODE" = rehearsal ]; then
  SIZES="1,2"; CHUNKS="1,16"; REPS=2; REPS_LARGE=2; CAP=1; BASE_MAX=2; TARGET=emulators
fi
COMMON=(--sizes-mib "$SIZES" --chunks-mib "$CHUNKS" --repeats "$REPS" --repeats-large "$REPS_LARGE" --baseline-max-mib "$BASE_MAX")

echo "== Configuration: sizes $SIZES MiB, backend chunks $CHUNKS MiB, $REPS repeats ($REPS_LARGE at 1 GiB), byte cap $CAP GiB, target $TARGET"
$PY $RC plan --target "$TARGET" "${COMMON[@]}" 2>&1 | grep -v -E "Deprecat|starlette"
[ "$MODE" = dry ] && { echo "(dry run: nothing contacted)"; exit 0; }

ask() {   # ask VAR "label" [secret]
  local var=$1 label=$2 secret=${3:-}
  if [ -n "${!var:-}" ]; then return 0; fi
  if [ ! -t 0 ]; then echo "$var is not set and there is no terminal to ask for it." >&2; exit 2; fi
  if [ -n "$secret" ]; then read -rsp "$label (hidden): " "$var"; echo; else read -rp "$label: " "$var"; fi
  [ -n "${!var}" ] || { echo "$var is required." >&2; exit 2; }
  export "$var"
}

if [ "$MODE" = real ]; then
  echo
  echo "Enter the configuration for the DEDICATED, EMPTY, disposable test buckets (names must contain 'bench')."
  ask ZT_S3_BUCKET "S3 bucket name"
  ask ZT_S3_REGION "S3 region (e.g. ap-south-1)"
  ask AWS_ACCESS_KEY_ID "AWS access key id"
  ask AWS_SECRET_ACCESS_KEY "AWS secret access key" secret
  ask ZT_AZURE_CONTAINER "Azure container name"
  ask ZT_AZURE_CONNECTION_STRING "Azure connection string" secret
  ask ZT_GCS_BUCKET "GCS bucket name"
  ask ZT_GCS_PROJECT "GCP project id"
  ask GOOGLE_APPLICATION_CREDENTIALS "Path to the GCP service-account key file"
  ask HOST_LABEL "Where is this running (e.g. 'AWS t3.xlarge ap-south-1' or 'laptop, home broadband')"
else
  HOST_LABEL="rehearsal on emulators"
fi

echo; echo "== Preflight"
$PY $RC preflight --target "$TARGET" 2>&1 | grep -v -E "Deprecat|starlette"

if [ "$MODE" = real ]; then
  echo
  read -rp "Type YES to start the run (it moves the volume shown above and deletes every object in the three buckets afterwards): " ok
  [ "$ok" = YES ] || { echo "Not confirmed. Nothing was run."; exit 0; }
fi

OUT="../scripts/bench/results/phase4-$TARGET-$(date +%Y%m%d-%H%M%S)"
echo; echo "== Run -> $OUT"
$PY $RC run --target "$TARGET" "${COMMON[@]}" --max-transfer-gib "$CAP" --host-label "$HOST_LABEL" --out "$OUT" 2>&1 | grep -v -E "Deprecat|starlette"
$PY $RC summarize "$OUT" 2>&1 | grep -v -E "Deprecat|starlette" | tee "$OUT/SUMMARY.md"

unset AWS_SECRET_ACCESS_KEY ZT_AZURE_CONNECTION_STRING
echo
echo "Done. Results: $OUT   (send this folder; it contains timings only, no credentials)"
if [ "$MODE" = real ]; then
  echo "Now: revoke the keys, delete the buckets / storage account / project resources / VM, and check each billing page tomorrow."
fi

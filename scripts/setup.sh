#!/usr/bin/env bash
# One-time setup: Python virtualenv + backend deps, Azurite emulator, frontend deps.
# Requires: Python 3.11+ and Node.js 20+ (with npm) on PATH. Linux or macOS (on Windows use WSL).
set -euo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PY="${PYTHON:-python3}"
"$PY" -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ required"'
command -v npm >/dev/null || { echo "npm (Node.js 20+) is required" >&2; exit 1; }

echo "[setup] backend virtualenv"
"$PY" -m venv "$REPO_DIR/backend/.venv"
"$REPO_DIR/backend/.venv/bin/pip" install -q --upgrade pip
"$REPO_DIR/backend/.venv/bin/pip" install -q -r "$REPO_DIR/backend/requirements.txt"

echo "[setup] Azurite (Azure Blob emulator)"
mkdir -p "$REPO_DIR/scripts/.emulators"
npm install --silent --no-fund --no-audit --prefix "$REPO_DIR/scripts/.emulators" azurite

echo "[setup] frontend"
(cd "$REPO_DIR/frontend" && npm ci --silent --no-fund --no-audit)

chmod +x "$REPO_DIR"/scripts/*.sh "$REPO_DIR"/scripts/attacks/*.sh 2>/dev/null || true
echo "[setup] done. Next: see QUICKSTART.md"

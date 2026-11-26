#!/usr/bin/env bash
# Reproduces the whole statistical analysis with one command (about an hour at the default n = 30):
#
#   bash analysis/run_all.sh            # full size, n = 30 per condition
#   N=5 bash analysis/run_all.sh        # quick check of the pipeline
#
# It installs analysis/requirements.txt into the backend virtualenv, starts the three local emulators, runs the attack suite
# (experiment h), collects the measurements (a to g), runs the whole backend suite under pytest-cov (experiment i), stops the
# emulators, then writes analysis/data/*.csv, analysis/figures/*, docs/STATISTICAL_ANALYSIS.md and analysis/statistical-analysis.pdf.
# Run it on an otherwise idle machine: other load changes the timings. Requires Linux, macOS or WSL (see QUICKSTART.md).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
PY=backend/.venv/bin/python
[ -x "$PY" ] || { echo "run 'bash scripts/setup.sh' first" >&2; exit 1; }
export PATH="$HOME/.local/node/bin:$PATH"
N="${N:-30}"
mkdir -p analysis/data analysis/figures

echo "== dependencies"; "$PY" -m pip install -q -r analysis/requirements.txt

echo "== emulators"
scripts/emulators.sh stop >/dev/null 2>&1 || true
for attempt in 1 2 3; do                       # Azurite can need longer than the start script waits on a cold start
  scripts/emulators.sh start >/dev/null 2>&1 || true
  [ "$(scripts/emulators.sh status | grep -c ' running ')" = 3 ] && break
  scripts/emulators.sh stop >/dev/null 2>&1 || true; sleep 2
done
scripts/emulators.sh status
[ "$(scripts/emulators.sh status | grep -c ' running ')" = 3 ] || { echo "the three emulators did not start" >&2; exit 1; }

echo "== h. attack suite"
scripts/attacks/run_all.sh --markdown > analysis/data/attacks_run.txt 2>&1
grep -E "^Totals" analysis/data/attacks_run.txt

echo "== a-g. measurements (n = $N)"
"$PY" analysis/collect.py --only a,b,c,d,e,f,g,h --n "$N"

echo "== i. engineering metrics and coverage"
"$PY" analysis/eng.py --coverage

scripts/emulators.sh stop >/dev/null 2>&1 || true

echo "== analysis and report"
"$PY" analysis/analyze.py
echo "done: docs/STATISTICAL_ANALYSIS.md and analysis/statistical-analysis.pdf"

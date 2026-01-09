#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PYTHON:-python3}"
BACKEND_DIR="backend"
VENV_DIR=".venv"

echo "[dev] Creating venv if missing..."
if [[ ! -d "$VENV_DIR" ]]; then
    "$PY" -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091

source "$VENV_DIR/bin/activate"

echo "[dev] Installing deps..."
if command -v uv >/dev/null 2>&1; then
    uv pip install -r "$BACKEND_DIR/requirements.txt"
else
    pip install -r "$BACKEND_DIR/requirements.txt"
fi

echo "[dev] Running tests..."
pytest -q "$BACKEND_DIR/tests" || true

echo "[dev] Starting backend..."
export PYTHONPATH="$BACKEND_DIR"
python -m uvicorn app.main:app --app-dir "$BACKEND_DIR" --host 127.0.0.1 --port 8000 --reload

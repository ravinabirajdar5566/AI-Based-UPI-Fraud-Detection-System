#!/usr/bin/env bash
# One-command start (Linux / macOS):  bash run.sh
set -e
cd "$(dirname "$0")"
python3 -m venv .venv 2>/dev/null || true
source .venv/bin/activate
pip install -q -r backend/requirements.txt
[ -f backend/models/model.pkl ] || python ml/train.py
cd backend
echo "Open http://127.0.0.1:8000"
uvicorn app.main:app --host 127.0.0.1 --port 8000

@echo off
REM One-command start (Windows):  run.bat
cd /d "%~dp0"
if not exist .venv python -m venv .venv
call .venv\Scripts\activate
pip install -q -r backend\requirements.txt
REM Re-train so the model matches YOUR scikit-learn version
python ml\train.py
cd backend
echo Open http://127.0.0.1:8000
uvicorn app.main:app --host 127.0.0.1 --port 8000

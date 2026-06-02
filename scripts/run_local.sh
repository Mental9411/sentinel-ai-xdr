#!/bin/bash
set -e
cd "$(dirname "$0")/.."

[ -f .env ] || cp .env.example .env

docker compose up -d postgres redis
sleep 5

pip install -r requirements.txt
export PYTHONPATH=.
export DATABASE_URL=postgresql+asyncpg://sentinel:sentinel_secure_password@localhost:5432/sentinel_xdr

uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 &
sleep 2
API_BASE_URL=http://localhost:8000 streamlit run dashboard/app.py --server.port 8501 &

echo "Sentinel-AI XDR running"
echo "  API: http://localhost:8000"
echo "  Dashboard: http://localhost:8501"

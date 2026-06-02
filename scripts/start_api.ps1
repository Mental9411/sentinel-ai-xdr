# Start API only (MongoDB required on port 27017)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot\..

$env:PYTHONPATH = (Get-Location).Path
$env:MONGODB_URL = "mongodb://localhost:27017"
$env:MONGODB_DB = "sentinel_xdr"

Write-Host "MongoDB required at mongodb://localhost:27017" -ForegroundColor Cyan
Write-Host "Starting API: http://127.0.0.1:8000" -ForegroundColor Cyan
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000

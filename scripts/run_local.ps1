# Sentinel-AI XDR - Local Startup (MongoDB + API + Dashboard)
$ErrorActionPreference = "Continue"
Set-Location $PSScriptRoot\..

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example" -ForegroundColor Green
}

function Test-CommandExists($Name) {
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Test-PortOpen($Port) {
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect("127.0.0.1", $Port)
        $tcp.Close()
        return $true
    }
    catch {
        return $false
    }
}

# MongoDB (or in-memory mock)
$env:MONGODB_USE_MOCK = "0"
if (-not (Test-PortOpen 27017)) {
    if (Test-CommandExists "docker") {
        Write-Host "Starting MongoDB via Docker..." -ForegroundColor Cyan
        docker rm -f sentinel-mongo 2>$null | Out-Null
        docker run -d --name sentinel-mongo -p 27017:27017 mongo:7-jammy 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "MongoDB container started on port 27017" -ForegroundColor Green
            Start-Sleep -Seconds 6
        }
        else {
            $env:MONGODB_USE_MOCK = "1"
            Write-Host "Using in-memory MongoDB mock (no Docker MongoDB)" -ForegroundColor Yellow
        }
    }
    else {
        $env:MONGODB_USE_MOCK = "1"
        Write-Host "MongoDB not on port 27017 - using in-memory mock (dev mode)" -ForegroundColor Yellow
        Write-Host "For persistent data: install MongoDB or Docker" -ForegroundColor Yellow
    }
}
else {
    Write-Host "MongoDB already running on port 27017" -ForegroundColor Green
}

if (-not (Test-PortOpen 6379) -and (Test-CommandExists "docker")) {
    docker run -d --name sentinel-redis -p 6379:6379 redis:7-alpine 2>$null | Out-Null
}

Write-Host ""
Write-Host "Installing Python dependencies..." -ForegroundColor Cyan
pip install fastapi uvicorn motor beanie pymongo mongomock-motor pydantic pydantic-settings email-validator python-jose passlib bcrypt pyotp qrcode httpx slowapi redis numpy pandas scikit-learn psutil scapy streamlit plotly streamlit-autorefresh pyvis networkx "watchdog>=4.0.0" --quiet 2>$null

$projectRoot = (Get-Location).Path
$mockFlag = $env:MONGODB_USE_MOCK
$env:PYTHONPATH = $projectRoot
$env:MONGODB_URL = "mongodb://localhost:27017"
$env:MONGODB_DB = "sentinel_xdr"

Write-Host "Database: MongoDB ($env:MONGODB_URL)" -ForegroundColor Cyan
Write-Host "Starting API on http://127.0.0.1:8000 ..." -ForegroundColor Cyan

$apiScript = "cd '$projectRoot'; `$env:PYTHONPATH='$projectRoot'; `$env:MONGODB_URL='mongodb://localhost:27017'; `$env:MONGODB_DB='sentinel_xdr'; `$env:MONGODB_USE_MOCK='$mockFlag'; python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000"
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Command", $apiScript

Write-Host "Waiting for API to start..." -ForegroundColor Cyan
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 2
    try {
        $r = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -TimeoutSec 3
        if ($r.status -eq "healthy") {
            $ready = $true
            break
        }
    }
    catch {
        # API not ready yet
    }
}
if ($ready) {
    Write-Host "API is healthy!" -ForegroundColor Green
}
else {
    Write-Host "API still starting - check the API window for errors" -ForegroundColor Yellow
    Write-Host "Wait for: Application startup complete" -ForegroundColor Yellow
    Start-Sleep -Seconds 8
    try {
        $r = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -TimeoutSec 5
        if ($r.status -eq "healthy" -or $r.status -eq "degraded") { $ready = $true }
    } catch { }
}

if (-not $ready) {
    Write-Host "WARNING: Dashboard may show 'Cannot reach API' until the API window is ready." -ForegroundColor Yellow
}

Write-Host "Stopping any existing Streamlit on port 8501..." -ForegroundColor Cyan
Get-NetTCPConnection -LocalPort 8501 -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }

Write-Host "Starting Dashboard on http://localhost:8501 ..." -ForegroundColor Cyan
$dashScript = "cd '$projectRoot'; `$env:PYTHONPATH='$projectRoot'; `$env:API_BASE_URL='http://127.0.0.1:8000'; streamlit run dashboard/app.py --server.port 8501 --server.fileWatcherType none --server.runOnSave false --client.showSidebarNavigation=false"
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Command", $dashScript

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host " Sentinel-AI XDR is running!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Dashboard:  http://localhost:8501"
Write-Host "  API Docs:   http://localhost:8000/api/docs"
Write-Host "  Admin:      admin@sentinel-xdr.com"
Write-Host "  Password:   Sentinel@Admin2024!"
Write-Host "  Database:   MongoDB (localhost:27017)"
Write-Host ""

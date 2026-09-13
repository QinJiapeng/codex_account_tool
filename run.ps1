$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    Write-Error "未找到 .venv，请先执行：python -m venv .venv；.venv\Scripts\python -m pip install -r requirements.txt"
}
$hostName = if ($env:APP_HOST) { $env:APP_HOST } else { "127.0.0.1" }
$portNumber = if ($env:APP_PORT) { [int]$env:APP_PORT } else { 10717 }
& $python -m uvicorn app.main:app --host $hostName --port $portNumber

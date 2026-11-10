# Opens one window each for the website, the WAF and the dashboard.
# Usage: .\scripts\start-all.ps1
$root = Split-Path -Parent $PSScriptRoot

Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$root\protected-site'; pnpm start"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$root\waf-backend'; .venv\Scripts\python.exe -m app.main"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$root\dashboard'; pnpm dev --port 3001"

Write-Host "Website through the WAF:  http://localhost:8000"
Write-Host "Dashboard:                http://localhost:3001"
Write-Host "Website directly:         http://localhost:3000 (must show 'Direct access is not allowed')"

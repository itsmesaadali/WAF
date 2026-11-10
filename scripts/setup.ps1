# First-time setup. Run from the project folder:  .\scripts\setup.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Step($text) { Write-Host "`n==> $text" -ForegroundColor Cyan }

Step "Creating .env and generating secrets (existing values are kept)"
py scripts\setup-env.py
if (Select-String -Path .env -Pattern "USER:PASSWORD" -Quiet) {
    Write-Host "Open .env, set DATABASE_URL and DATABASE_URL_UNPOOLED, then run this script again." -ForegroundColor Yellow
    exit 1
}

Step "Installing Python packages for the WAF"
if (-not (Test-Path waf-backend\.venv)) { py -m venv waf-backend\.venv }
& waf-backend\.venv\Scripts\python.exe -m pip install --quiet -r waf-backend\requirements-dev.txt
if ($LASTEXITCODE -ne 0) { throw "Python package install failed" }

Step "Installing Node packages"
pnpm install
if ($LASTEXITCODE -ne 0) { throw "Root package install failed" }
pnpm --dir protected-site install --ignore-workspace
if ($LASTEXITCODE -ne 0) { throw "Protected site install failed" }
pnpm --dir dashboard install --ignore-workspace
if ($LASTEXITCODE -ne 0) { throw "Dashboard install failed" }

Step "Creating database tables with Prisma"
pnpm db:deploy
if ($LASTEXITCODE -ne 0) { throw "Database migration failed" }

Step "Training the ML model"
Push-Location waf-backend
& .venv\Scripts\python.exe -m app.ml.train
$trainExit = $LASTEXITCODE
Pop-Location
if ($trainExit -ne 0) { throw "Model training failed" }

if (-not (Test-Path dashboard\.env.local)) {
    Set-Content -Path dashboard\.env.local -Encoding ascii -Value "WAF_API_URL=http://127.0.0.1:8000"
}

Write-Host "`nSetup finished. Start everything with:  .\scripts\start-all.ps1" -ForegroundColor Green

# Runs automated tests. The integration tests start their own copies of the WAF and website
# on ports 8100 and 3100, and use a separate waf_test database schema.
# Usage: .\scripts\test.ps1            all tests
#        .\scripts\test.ps1 -UnitOnly  fast tests, no database needed
param([switch]$UnitOnly)

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$python = "waf-backend\.venv\Scripts\python.exe"

pnpm --dir protected-site test
$siteExit = $LASTEXITCODE

# The Chrome extension's engine must agree with the Python WAF.
node --test browser-extension/test/engine.test.js browser-extension/test/grade.test.js
$extensionExit = $LASTEXITCODE

if ($UnitOnly) {
    & $python -m pytest tests/unit -q
} else {
    & $python -m pytest -q
}
$pythonExit = $LASTEXITCODE

if ($siteExit -ne 0 -or $extensionExit -ne 0 -or $pythonExit -ne 0) { exit 1 }

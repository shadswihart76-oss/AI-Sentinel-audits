Set-Location -Path $PSScriptRoot

if (Get-Command python -ErrorAction SilentlyContinue) {
    python -m openclaw.dashboard
    exit $LASTEXITCODE
}

if (Get-Command python3 -ErrorAction SilentlyContinue) {
    python3 -m openclaw.dashboard
    exit $LASTEXITCODE
}

Write-Host "Python was not found in PATH. Install Python and retry."

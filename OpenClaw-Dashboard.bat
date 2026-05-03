@echo off
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if %errorlevel%==0 (
  python -m openclaw.dashboard
  goto :eof
)

where python3 >nul 2>nul
if %errorlevel%==0 (
  python3 -m openclaw.dashboard
  goto :eof
)

echo Python was not found in PATH.
echo Install Python and try again.
pause

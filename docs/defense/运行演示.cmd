@echo off
chcp 65001 >nul
cd /d "%~dp0..\.."

echo [defense-demo] running the 3-minute live demonstration
echo [defense-demo] repo root: %CD%
echo.

python -B scripts\defense_demo.py %*

if errorlevel 1 (
  echo.
  echo [FAILED] Do not debug on stage. Use the frozen fallback instead:
  echo   python -B scripts\defense_demo.py --rundir reports\technical-exploration\2026-09-12
  echo.
  pause
)

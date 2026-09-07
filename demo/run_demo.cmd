@echo off
setlocal
cd /d "%~dp0.."
uv sync --locked
if errorlevel 1 exit /b 1
uv run python demo/scripts/local_smoke.py --learn
exit /b %errorlevel%

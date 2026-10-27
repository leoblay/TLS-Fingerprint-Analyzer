@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo [1/2] Creating virtual environment...
  py -3.12 -m venv .venv || goto :error
  echo [2/2] Installing dependencies...
  .venv\Scripts\python.exe -m pip install -r requirements.txt || goto :error
)

echo Starting dashboard at http://127.0.0.1:5000
.venv\Scripts\python.exe app.py
goto :end

:error
echo.
echo Setup failed. Confirm Python 3.12 is installed, then run this file again.
pause

:end
endlocal


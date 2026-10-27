@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo Python environment is missing. Run run.bat once first.
  pause
  exit /b 1
)

.venv\Scripts\python.exe -m pip install pyinstaller || goto :error
.venv\Scripts\pyinstaller.exe --noconfirm --clean --onefile --name TLSFingerprintDemo --collect-all selenium --add-data "templates;templates" --add-data "static;static" app.py || goto :error
copy /Y README-distribution.txt dist\README-distribution.txt >nul

echo.
echo Complete: dist\TLSFingerprintDemo.exe
echo Distribute this EXE with README-distribution.txt.
pause
goto :end

:error
echo Build failed.
pause

:end
endlocal


@echo off
echo Windows Autorun Analyzer - Simple Mode
echo ======================================
echo.
echo Running auto-detect mode...
echo.

powershell.exe -ExecutionPolicy Bypass -File "WindowsAutorunAnalyzer_Universal.ps1"

echo.
echo Analysis complete!
pause

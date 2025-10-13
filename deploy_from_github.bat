@echo off
REM Windows Autorun Analyzer - GitHub Deployment
REM Copy this entire file content and paste into any Windows system

echo Windows Autorun Analyzer - GitHub Deployment
echo ============================================
echo.

echo Downloading and running Windows Autorun Analyzer from GitHub...
echo Repository: https://github.com/monobrau/windows-autorun-analyzer
echo.

REM The one-liner command:
powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/monobrau/windows-autorun-analyzer/main/WindowsAutorunAnalyzer_Universal.ps1' -OutFile 'autorun.ps1'; .\autorun.ps1"

echo.
echo Analysis complete!
echo Check for AutorunAnalysis_*.csv file in current directory.
pause

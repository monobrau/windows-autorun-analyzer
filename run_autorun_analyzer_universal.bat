@echo off
echo ========================================
echo Windows Autorun Analyzer - Universal
echo ========================================
echo.

echo Select mode:
echo 1. Auto-detect (Recommended)
echo 2. GitHub download
echo 3. Local script
echo 4. LAN share
echo 5. Portable mode (No dependencies)
echo 6. Show help
echo.

set /p choice="Enter your choice (1-6): "

if "%choice%"=="1" (
    echo Running auto-detect mode...
    powershell.exe -ExecutionPolicy Bypass -File "WindowsAutorunAnalyzer_Universal.ps1" -Mode auto
) else if "%choice%"=="2" (
    echo Running GitHub mode...
    powershell.exe -ExecutionPolicy Bypass -File "WindowsAutorunAnalyzer_Universal.ps1" -Mode github
) else if "%choice%"=="3" (
    echo Running local mode...
    powershell.exe -ExecutionPolicy Bypass -File "WindowsAutorunAnalyzer_Universal.ps1" -Mode local
) else if "%choice%"=="4" (
    set /p sharepath="Enter share path (e.g., \\server\share\script.ps1): "
    echo Running share mode...
    powershell.exe -ExecutionPolicy Bypass -File "WindowsAutorunAnalyzer_Universal.ps1" -Mode share -SharePath "%sharepath%"
) else if "%choice%"=="5" (
    echo Running portable mode...
    powershell.exe -ExecutionPolicy Bypass -File "WindowsAutorunAnalyzer_Universal.ps1" -Mode portable
) else if "%choice%"=="6" (
    powershell.exe -ExecutionPolicy Bypass -File "WindowsAutorunAnalyzer_Universal.ps1" -Help
    pause
    goto :eof
) else (
    echo Invalid choice. Running auto-detect mode...
    powershell.exe -ExecutionPolicy Bypass -File "WindowsAutorunAnalyzer_Universal.ps1" -Mode auto
)

echo.
echo Analysis complete!
pause

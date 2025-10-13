@echo off
echo ========================================
echo Windows Autorun Analyzer - Advanced
echo ========================================
echo.

echo Select deployment method:
echo 1. Auto-detect (Recommended)
echo 2. GitHub download
echo 3. Local script
echo 4. LAN share
echo 5. Portable version only
echo.

set /p choice="Enter your choice (1-5): "

if "%choice%"=="1" (
    echo Running auto-detect mode...
    powershell.exe -ExecutionPolicy Bypass -File "WindowsAutorunAnalyzer_Launcher.ps1"
) else if "%choice%"=="2" (
    echo Running GitHub mode...
    powershell.exe -ExecutionPolicy Bypass -File "Deploy_GitHub.ps1"
) else if "%choice%"=="3" (
    echo Running local mode...
    powershell.exe -ExecutionPolicy Bypass -File "Deploy_Local.ps1"
) else if "%choice%"=="4" (
    set /p sharepath="Enter share path (e.g., \\server\share\script.ps1): "
    echo Running share mode...
    powershell.exe -ExecutionPolicy Bypass -File "Deploy_Share.ps1" -SharePath "%sharepath%"
) else if "%choice%"=="5" (
    echo Running portable version...
    powershell.exe -ExecutionPolicy Bypass -File "WindowsAutorunAnalyzer_Portable.ps1"
) else (
    echo Invalid choice. Running auto-detect mode...
    powershell.exe -ExecutionPolicy Bypass -File "WindowsAutorunAnalyzer_Launcher.ps1"
)

echo.
echo Analysis complete!
pause

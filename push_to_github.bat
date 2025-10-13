@echo off
echo ========================================
echo Windows Autorun Analyzer - GitHub Push
echo ========================================
echo.

echo This will help you push the Windows Autorun Analyzer to GitHub.
echo.

set /p username="Enter your GitHub username: "

if "%username%"=="" (
    echo Error: GitHub username is required
    pause
    exit /b 1
)

echo.
echo GitHub Username: %username%
echo Repository Name: windows-autorun-analyzer
echo.

set /p confirm="Proceed with GitHub deployment? (y/n): "

if /i not "%confirm%"=="y" (
    echo Deployment cancelled
    pause
    exit /b 0
)

echo.
echo Running PowerShell deployment script...
echo.

powershell.exe -ExecutionPolicy Bypass -File "Push_to_GitHub.ps1" -GitHubUsername "%username%"

echo.
echo GitHub deployment process completed!
pause

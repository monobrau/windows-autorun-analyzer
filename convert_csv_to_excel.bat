@echo off
REM Convert CSV to Excel with Color Coding
REM Usage: convert_csv_to_excel.bat [csv_file_or_directory]

setlocal

if "%1"=="" (
    echo CSV to Excel Converter for Windows Autorun Analyzer
    echo ==================================================
    echo.
    echo Usage:
    echo   convert_csv_to_excel.bat "path\to\file.csv"
    echo   convert_csv_to_excel.bat "path\to\directory"
    echo   convert_csv_to_excel.bat "path\to\directory" -Recursive
    echo.
    echo Examples:
    echo   convert_csv_to_excel.bat "AutorunAnalysis_20250113_140657.csv"
    echo   convert_csv_to_excel.bat "C:\temp"
    echo   convert_csv_to_excel.bat "C:\temp" -Recursive
    echo.
    pause
    exit /b 1
)

REM Check if PowerShell is available
powershell -Command "Get-Host" >nul 2>&1
if errorlevel 1 (
    echo Error: PowerShell is not available or not working properly.
    pause
    exit /b 1
)

REM Run the PowerShell script
if "%2"=="-Recursive" (
    powershell -ExecutionPolicy Bypass -Command "& '%~dp0Convert-CSV-to-Excel.ps1' -CsvPath '%1' -Recursive"
) else (
    powershell -ExecutionPolicy Bypass -Command "& '%~dp0Convert-CSV-to-Excel.ps1' -CsvPath '%1'"
)

if errorlevel 1 (
    echo.
    echo Conversion failed. Check the error messages above.
    pause
    exit /b 1
) else (
    echo.
    echo Conversion completed successfully!
    pause
)

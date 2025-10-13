# Windows Autorun Analyzer - GitHub Deployment Script
# Copy this entire file content and paste into any Windows system

Write-Host "Windows Autorun Analyzer - GitHub Deployment" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Downloading and running Windows Autorun Analyzer from GitHub..." -ForegroundColor Yellow
Write-Host "Repository: https://github.com/monobrau/windows-autorun-analyzer" -ForegroundColor Gray
Write-Host ""

# The one-liner command:
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/monobrau/windows-autorun-analyzer/main/WindowsAutorunAnalyzer_Universal.ps1" -OutFile "autorun.ps1"; .\autorun.ps1

Write-Host ""
Write-Host "Analysis complete!" -ForegroundColor Green
Write-Host "Check for AutorunAnalysis_*.csv file in current directory." -ForegroundColor Yellow

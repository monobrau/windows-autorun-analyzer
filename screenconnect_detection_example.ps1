# ScreenConnect Detection Example
# This demonstrates how the Windows Autorun Analyzer detects ScreenConnect

Write-Host "ScreenConnect Detection Examples:" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# Example 1: ScreenConnect in registry
$regExample = "C:\Program Files (x86)\ScreenConnect Client\ScreenConnect.ClientService.exe"
Write-Host "`nRegistry Example:" -ForegroundColor Yellow
Write-Host "Command: $regExample"
Write-Host "Detection: RMM/Remote Desktop software detected" -ForegroundColor Red

# Example 2: ScreenConnect in startup folder
$startupExample = "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\ScreenConnect.lnk"
Write-Host "`nStartup Folder Example:" -ForegroundColor Yellow
Write-Host "Command: $startupExample"
Write-Host "Detection: RMM/Remote Desktop software detected" -ForegroundColor Red

# Example 3: ScreenConnect service
$serviceExample = "C:\Program Files\ScreenConnect\ScreenConnect.Service.exe"
Write-Host "`nService Example:" -ForegroundColor Yellow
Write-Host "Command: $serviceExample"
Write-Host "Detection: RMM/Remote Desktop software detected" -ForegroundColor Red

# Example 4: ScreenConnect scheduled task
$taskExample = "C:\Windows\System32\ScreenConnect\ScreenConnect.exe"
Write-Host "`nScheduled Task Example:" -ForegroundColor Yellow
Write-Host "Command: $taskExample"
Write-Host "Detection: RMM/Remote Desktop software detected" -ForegroundColor Red

Write-Host "`nAll ScreenConnect instances will be flagged as RED (Suspicious)" -ForegroundColor Green
Write-Host "This includes detection by:" -ForegroundColor Green
Write-Host "- Path patterns containing 'screenconnect'" -ForegroundColor White
Write-Host "- Publisher information from digital signatures" -ForegroundColor White
Write-Host "- Command line arguments" -ForegroundColor White

Write-Host "`nTo run the full analysis:" -ForegroundColor Cyan
Write-Host ".\WindowsAutorunAnalyzer_Universal.ps1" -ForegroundColor White

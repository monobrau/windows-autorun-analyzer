# Windows Autorun Analyzer Launcher
# Handles multiple deployment scenarios: GitHub, Local, and LAN Share

param(
    [string]$Mode = "auto",  # auto, github, local, share
    [string]$GitHubUrl = "https://raw.githubusercontent.com/yourusername/windows-autorun-analyzer/main/WindowsAutorunAnalyzer.ps1",
    [string]$SharePath = "\\server\share\WindowsAutorunAnalyzer.ps1",
    [string]$LocalPath = ".\WindowsAutorunAnalyzer.ps1",
    [string]$OutputPath = "C:\dev\AutorunAnalysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').xlsx"
)

function Write-Status {
    param($Message, $Color = "White")
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $Color
}

function Test-InternetConnection {
    try {
        $response = Invoke-WebRequest -Uri "https://www.google.com" -TimeoutSec 5 -UseBasicParsing
        return $true
    } catch {
        return $false
    }
}

function Get-ScriptFromGitHub {
    param($Url, $OutputFile)
    
    Write-Status "Downloading script from GitHub..." "Yellow"
    try {
        $scriptContent = Invoke-WebRequest -Uri $Url -UseBasicParsing
        $scriptContent.Content | Out-File -FilePath $OutputFile -Encoding UTF8
        Write-Status "Script downloaded successfully" "Green"
        return $true
    } catch {
        Write-Status "Failed to download from GitHub: $($_.Exception.Message)" "Red"
        return $false
    }
}

function Get-ScriptFromShare {
    param($SharePath, $OutputFile)
    
    Write-Status "Copying script from LAN share..." "Yellow"
    try {
        if (Test-Path $SharePath) {
            Copy-Item -Path $SharePath -Destination $OutputFile -Force
            Write-Status "Script copied from share successfully" "Green"
            return $true
        } else {
            Write-Status "Script not found at share path: $SharePath" "Red"
            return $false
        }
    } catch {
        Write-Status "Failed to copy from share: $($_.Exception.Message)" "Red"
        return $false
    }
}

function Get-ScriptLocally {
    param($LocalPath, $OutputFile)
    
    Write-Status "Using local script..." "Yellow"
    try {
        if (Test-Path $LocalPath) {
            Copy-Item -Path $LocalPath -Destination $OutputFile -Force
            Write-Status "Local script found and copied" "Green"
            return $true
        } else {
            Write-Status "Local script not found at: $LocalPath" "Red"
            return $false
        }
    } catch {
        Write-Status "Failed to use local script: $($_.Exception.Message)" "Red"
        return $false
    }
}

function Show-Usage {
    Write-Host @"
Windows Autorun Analyzer Launcher
=================================

Usage: .\WindowsAutorunAnalyzer_Launcher.ps1 [parameters]

Parameters:
  -Mode <string>        : auto, github, local, share (default: auto)
  -GitHubUrl <string>   : GitHub raw URL for script download
  -SharePath <string>   : UNC path to script on LAN share
  -LocalPath <string>   : Local path to script file
  -OutputPath <string>  : Output path for analysis results

Examples:
  # Auto-detect best method
  .\WindowsAutorunAnalyzer_Launcher.ps1

  # Force GitHub download
  .\WindowsAutorunAnalyzer_Launcher.ps1 -Mode github

  # Use local script
  .\WindowsAutorunAnalyzer_Launcher.ps1 -Mode local

  # Use LAN share
  .\WindowsAutorunAnalyzer_Launcher.ps1 -Mode share -SharePath "\\server\share\script.ps1"

Deployment Scenarios:
1. With Internet: Downloads from GitHub automatically
2. No Internet: Uses local script or LAN share
3. LAN Share: Copies from network location

"@
}

# Main execution
Write-Status "Windows Autorun Analyzer Launcher Starting..." "Cyan"
Write-Status "Mode: $Mode" "Cyan"

# Create output directory if it doesn't exist
$outputDir = Split-Path $OutputPath -Parent
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$scriptPath = Join-Path $outputDir "WindowsAutorunAnalyzer.ps1"
$success = $false

switch ($Mode.ToLower()) {
    "github" {
        Write-Status "Forcing GitHub download mode" "Yellow"
        $success = Get-ScriptFromGitHub -Url $GitHubUrl -OutputFile $scriptPath
    }
    "local" {
        Write-Status "Forcing local script mode" "Yellow"
        $success = Get-ScriptLocally -LocalPath $LocalPath -OutputFile $scriptPath
    }
    "share" {
        Write-Status "Forcing LAN share mode" "Yellow"
        $success = Get-ScriptFromShare -SharePath $SharePath -OutputFile $scriptPath
    }
    "auto" {
        Write-Status "Auto-detecting best method..." "Yellow"
        
        # Try GitHub first if internet is available
        if (Test-InternetConnection) {
            Write-Status "Internet connection detected, trying GitHub..." "Green"
            $success = Get-ScriptFromGitHub -Url $GitHubUrl -OutputFile $scriptPath
            
            if (-not $success) {
                Write-Status "GitHub failed, trying local script..." "Yellow"
                $success = Get-ScriptLocally -LocalPath $LocalPath -OutputFile $scriptPath
            }
        } else {
            Write-Status "No internet connection, trying local script..." "Yellow"
            $success = Get-ScriptLocally -LocalPath $LocalPath -OutputFile $scriptPath
            
            if (-not $success) {
                Write-Status "Local script not found, trying LAN share..." "Yellow"
                $success = Get-ScriptFromShare -SharePath $SharePath -OutputFile $scriptPath
            }
        }
    }
    default {
        Write-Status "Invalid mode specified. Use: auto, github, local, or share" "Red"
        Show-Usage
        exit 1
    }
}

if (-not $success) {
    Write-Status "Failed to obtain script from any source!" "Red"
    Write-Status "Please ensure you have:" "Yellow"
    Write-Status "1. Internet connection for GitHub mode" "Yellow"
    Write-Status "2. Local script file for local mode" "Yellow"
    Write-Status "3. Access to LAN share for share mode" "Yellow"
    Show-Usage
    exit 1
}

# Execute the script
Write-Status "Executing Windows Autorun Analyzer..." "Green"
try {
    & $scriptPath -OutputPath $OutputPath
    Write-Status "Analysis completed successfully!" "Green"
} catch {
    Write-Status "Error executing script: $($_.Exception.Message)" "Red"
    exit 1
}

Write-Status "Launcher completed!" "Cyan"

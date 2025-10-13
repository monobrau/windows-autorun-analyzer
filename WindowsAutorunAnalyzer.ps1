# Windows Autorun Analyzer
# Analyzes autoruns, scheduled tasks, services, and registry keys for all users
# Outputs results to Excel with color-coded indicators

param(
    [string]$OutputPath = "C:\dev\AutorunAnalysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').xlsx"
)

# Import required modules
try {
    Import-Module -Name ImportExcel -ErrorAction Stop
} catch {
    Write-Host "Installing ImportExcel module..." -ForegroundColor Yellow
    try {
        Install-Module -Name ImportExcel -Force -Scope CurrentUser -AllowClobber
        Import-Module -Name ImportExcel
        Write-Host "ImportExcel module installed successfully" -ForegroundColor Green
    } catch {
        Write-Warning "Could not install ImportExcel module. Will use CSV output instead."
        $UseCSV = $true
    }
}

# Initialize results arrays
$AllResults = @()
$BaselineItems = @()
$SuspiciousItems = @()

# Define baseline Windows items (common legitimate autoruns)
$BaselinePatterns = @(
    "C:\Windows\System32\*",
    "C:\Program Files\*",
    "C:\Program Files (x86)\*",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*",
    "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*",
    "*\Microsoft\Windows\Start Menu\Programs\Startup\*",
    "*\Windows\System32\*",
    "*\Windows\SysWOW64\*"
)

# Define suspicious patterns
$SuspiciousPatterns = @(
    "*\temp\*",
    "*\tmp\*",
    "*\AppData\Local\Temp\*",
    "*\AppData\Roaming\Temp\*",
    "*\Users\Public\*",
    "*\Windows\Temp\*",
    "*\Temporary Internet Files\*",
    "*\Downloads\*",
    "*\Desktop\*",
    "*\Documents\*"
)

# Function to check if item is suspicious or baseline
function Test-SuspiciousItem {
    param($Path, $Command)
    
    $suspicious = $false
    $isBaseline = $false
    $reason = ""
    
    # Check if it's a baseline Windows item
    if ($Command -match "^C:\\Windows\\" -or 
        $Command -match "^C:\\Program Files\\" -or
        $Command -match "^C:\\Program Files \\(x86\\)\\" -or
        $Command -match "C:\\Windows\\System32\\" -or
        $Command -match "C:\\Windows\\SysWOW64\\" -or
        $Command -match "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" -or
        $Command -match "C:\\Users\\.*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\") {
        $isBaseline = $true
    }
    
    # Check for PowerShell/CMD in suspicious locations
    if ($Command -match "powershell|cmd|wscript|cscript|mshta|rundll32" -and 
        ($Path -match "temp|tmp|downloads|desktop|documents|public" -or 
         $Command -match "temp|tmp|downloads|desktop|documents|public")) {
        $suspicious = $true
        $reason = "PowerShell/CMD in suspicious location"
    }
    
    # Check for non-standard locations (only if not baseline)
    if (-not $isBaseline -and 
        $Command -notmatch "C:\\Windows|C:\\Program Files|C:\\ProgramData" -and 
        $Command -notmatch "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup") {
        if ($reason) { $reason += "; " }
        $reason += "Non-standard location"
    }
    
    # Check for suspicious file extensions
    if ($Command -match "\.(bat|cmd|ps1|vbs|js|jar|exe)$" -and 
        $Command -match "temp|tmp|downloads|desktop|documents|public") {
        if ($reason) { $reason += "; " }
        $reason += "Suspicious file type in temp location"
    }
    
    return @{
        IsSuspicious = $suspicious
        IsBaseline = $isBaseline
        Reason = $reason
    }
}

# Function to get all user profiles
function Get-AllUserProfiles {
    $profiles = @()
    
    # Get local users
    $localUsers = Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.LocalPath -and $_.Special -eq $false }
    foreach ($user in $localUsers) {
        $profiles += @{
            Username = $user.LocalPath.Split('\')[-1]
            ProfilePath = $user.LocalPath
            SID = $user.SID
        }
    }
    
    # Add system accounts
    $profiles += @{
        Username = "SYSTEM"
        ProfilePath = "C:\Windows\System32\config\systemprofile"
        SID = "S-1-5-18"
    }
    
    $profiles += @{
        Username = "LOCAL SERVICE"
        ProfilePath = "C:\Windows\ServiceProfiles\LocalService"
        SID = "S-1-5-19"
    }
    
    $profiles += @{
        Username = "NETWORK SERVICE"
        ProfilePath = "C:\Windows\ServiceProfiles\NetworkService"
        SID = "S-1-5-20"
    }
    
    return $profiles
}

# Function to analyze registry autoruns
function Get-RegistryAutoruns {
    param($Username, $ProfilePath, $SID)
    
    $autoruns = @()
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler"
    )
    
    # Add user-specific registry paths if profile exists
    if (Test-Path $ProfilePath) {
        $userRegPath = "HKU:\$SID"
        if (Test-Path $userRegPath) {
            $regPaths += @(
                "$userRegPath\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "$userRegPath\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                "$userRegPath\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
                "$userRegPath\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
            )
        }
    }
    
    foreach ($regPath in $regPaths) {
        try {
            if (Test-Path $regPath) {
                $regItems = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                if ($regItems) {
                    $regItems.PSObject.Properties | Where-Object { 
                        $_.Name -notmatch "PSPath|PSParentPath|PSChildName|PSDrive|PSProvider" -and 
                        $_.Value -and 
                        $_.Value -ne "" 
                    } | ForEach-Object {
                        $suspicious = Test-SuspiciousItem -Path $_.Value -Command $_.Value
                        $status = if ($suspicious.IsSuspicious) { "RED" } elseif ($suspicious.IsBaseline) { "WHITE" } else { "YELLOW" }
                        $autoruns += [PSCustomObject]@{
                            User = $Username
                            Type = "Registry"
                            Location = $regPath
                            Name = $_.Name
                            Command = $_.Value
                            IsSuspicious = $suspicious.IsSuspicious
                            IsBaseline = $suspicious.IsBaseline
                            Reason = $suspicious.Reason
                            Status = $status
                        }
                    }
                }
            }
        } catch {
            Write-Warning "Could not access registry path: $regPath"
        }
    }
    
    return $autoruns
}

# Function to analyze startup folders
function Get-StartupFolderAutoruns {
    param($Username, $ProfilePath)
    
    $autoruns = @()
    $startupPaths = @(
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "C:\Users\$Username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    foreach ($startupPath in $startupPaths) {
        try {
            if (Test-Path $startupPath -ErrorAction SilentlyContinue) {
                Get-ChildItem -Path $startupPath -File -ErrorAction SilentlyContinue | ForEach-Object {
                    $suspicious = Test-SuspiciousItem -Path $_.FullName -Command $_.FullName
                    $status = if ($suspicious.IsSuspicious) { "RED" } elseif ($suspicious.IsBaseline) { "WHITE" } else { "YELLOW" }
                    $autoruns += [PSCustomObject]@{
                        User = $Username
                        Type = "Startup Folder"
                        Location = $startupPath
                        Name = $_.Name
                        Command = $_.FullName
                        IsSuspicious = $suspicious.IsSuspicious
                        IsBaseline = $suspicious.IsBaseline
                        Reason = $suspicious.Reason
                        Status = $status
                    }
                }
            }
        } catch {
            Write-Warning "Could not access startup folder: $startupPath"
        }
    }
    
    return $autoruns
}

# Function to analyze scheduled tasks
function Get-ScheduledTasks {
    $tasks = @()
    
    try {
        $allTasks = Get-ScheduledTask | Where-Object { $_.State -eq "Running" -or $_.State -eq "Ready" }
        foreach ($task in $allTasks) {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
            $taskActions = $task.Actions
            
            foreach ($action in $taskActions) {
                if ($action.Execute) {
                    $suspicious = Test-SuspiciousItem -Path $action.Execute -Command $action.Execute
                    $status = if ($suspicious.IsSuspicious) { "RED" } elseif ($suspicious.IsBaseline) { "WHITE" } else { "YELLOW" }
                    $tasks += [PSCustomObject]@{
                        User = "SYSTEM"
                        Type = "Scheduled Task"
                        Location = $task.TaskPath
                        Name = $task.TaskName
                        Command = $action.Execute
                        Arguments = $action.Arguments
                        IsSuspicious = $suspicious.IsSuspicious
                        IsBaseline = $suspicious.IsBaseline
                        Reason = $suspicious.Reason
                        Status = $status
                    }
                }
            }
        }
    } catch {
        Write-Warning "Could not enumerate scheduled tasks: $($_.Exception.Message)"
    }
    
    return $tasks
}

# Function to analyze services
function Get-Services {
    $services = @()
    
    try {
        $allServices = Get-WmiObject -Class Win32_Service | Where-Object { 
            $_.StartMode -eq "Auto" -or $_.StartMode -eq "Manual" 
        }
        
        foreach ($service in $allServices) {
            if ($service.PathName) {
                $suspicious = Test-SuspiciousItem -Path $service.PathName -Command $service.PathName
                $status = if ($suspicious.IsSuspicious) { "RED" } elseif ($suspicious.IsBaseline) { "WHITE" } else { "YELLOW" }
                $services += [PSCustomObject]@{
                    User = "SYSTEM"
                    Type = "Service"
                    Location = "Services"
                    Name = $service.Name
                    Command = $service.PathName
                    StartMode = $service.StartMode
                    State = $service.State
                    IsSuspicious = $suspicious.IsSuspicious
                    IsBaseline = $suspicious.IsBaseline
                    Reason = $suspicious.Reason
                    Status = $status
                }
            }
        }
    } catch {
        Write-Warning "Could not enumerate services: $($_.Exception.Message)"
    }
    
    return $services
}

# Function to analyze logon scripts
function Get-LogonScripts {
    $scripts = @()
    
    try {
        # Group Policy logon scripts
        $gpoScripts = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts" -ErrorAction SilentlyContinue
        if ($gpoScripts) {
            # This would need more detailed parsing of GPO scripts
        }
        
        # User logon scripts from registry
        $userProfiles = Get-AllUserProfiles
        foreach ($profile in $userProfiles) {
            if ($profile.SID -and $profile.SID -ne "S-1-5-18" -and $profile.SID -ne "S-1-5-19" -and $profile.SID -ne "S-1-5-20") {
                $logonScriptPath = "HKU:\$($profile.SID)\Environment"
                if (Test-Path $logonScriptPath) {
                    $logonScript = Get-ItemProperty -Path $logonScriptPath -Name "UserInitMprLogonScript" -ErrorAction SilentlyContinue
                    if ($logonScript -and $logonScript.UserInitMprLogonScript) {
                        $suspicious = Test-SuspiciousItem -Path $logonScript.UserInitMprLogonScript -Command $logonScript.UserInitMprLogonScript
                        $status = if ($suspicious.IsSuspicious) { "RED" } elseif ($suspicious.IsBaseline) { "WHITE" } else { "YELLOW" }
                        $scripts += [PSCustomObject]@{
                            User = $profile.Username
                            Type = "Logon Script"
                            Location = $logonScriptPath
                            Name = "UserInitMprLogonScript"
                            Command = $logonScript.UserInitMprLogonScript
                            IsSuspicious = $suspicious.IsSuspicious
                            IsBaseline = $suspicious.IsBaseline
                            Reason = $suspicious.Reason
                            Status = $status
                        }
                    }
                }
            }
        }
    } catch {
        Write-Warning "Could not enumerate logon scripts: $($_.Exception.Message)"
    }
    
    return $scripts
}

# Main execution
Write-Host "Starting Windows Autorun Analysis..." -ForegroundColor Green
Write-Host "Output will be saved to: $OutputPath" -ForegroundColor Yellow

# Get all user profiles
$userProfiles = Get-AllUserProfiles
Write-Host "Found $($userProfiles.Count) user profiles to analyze" -ForegroundColor Cyan

# Analyze each user
foreach ($profile in $userProfiles) {
    Write-Host "Analyzing user: $($profile.Username)" -ForegroundColor Cyan
    
    # Registry autoruns
    $registryAutoruns = Get-RegistryAutoruns -Username $profile.Username -ProfilePath $profile.ProfilePath -SID $profile.SID
    $AllResults += $registryAutoruns
    
    # Startup folder autoruns
    $startupAutoruns = Get-StartupFolderAutoruns -Username $profile.Username -ProfilePath $profile.ProfilePath
    $AllResults += $startupAutoruns
}

# Analyze system-wide items
Write-Host "Analyzing system-wide items..." -ForegroundColor Cyan

# Scheduled tasks
$scheduledTasks = Get-ScheduledTasks
$AllResults += $scheduledTasks

# Services
$services = Get-Services
$AllResults += $services

# Logon scripts
$logonScripts = Get-LogonScripts
$AllResults += $logonScripts

# Create output with color coding
Write-Host "Creating output..." -ForegroundColor Green

if ($UseCSV -or !(Get-Command Export-Excel -ErrorAction SilentlyContinue)) {
    # Use CSV output
    $csvPath = $OutputPath -replace '\.xlsx$', '.csv'
    $AllResults | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "Results saved to CSV: $csvPath" -ForegroundColor Yellow
} else {
    try {
        # Create Excel file
        $excel = $AllResults | Export-Excel -Path $OutputPath -AutoSize -TableStyle Medium2 -PassThru
        
        # Get the worksheet
        $ws = $excel.Workbook.Worksheets[0]
        
        # Add color coding
        $row = 2  # Start from row 2 (skip header)
        foreach ($result in $AllResults) {
            if ($result.Status -eq "RED") {
                $ws.Cells.Item($row, 1).Interior.Color = [System.Drawing.Color]::LightCoral
                $ws.Cells.Item($row, 2).Interior.Color = [System.Drawing.Color]::LightCoral
                $ws.Cells.Item($row, 3).Interior.Color = [System.Drawing.Color]::LightCoral
                $ws.Cells.Item($row, 4).Interior.Color = [System.Drawing.Color]::LightCoral
                $ws.Cells.Item($row, 5).Interior.Color = [System.Drawing.Color]::LightCoral
                $ws.Cells.Item($row, 6).Interior.Color = [System.Drawing.Color]::LightCoral
                $ws.Cells.Item($row, 7).Interior.Color = [System.Drawing.Color]::LightCoral
                $ws.Cells.Item($row, 8).Interior.Color = [System.Drawing.Color]::LightCoral
            } elseif ($result.Status -eq "YELLOW") {
                $ws.Cells.Item($row, 1).Interior.Color = [System.Drawing.Color]::LightYellow
                $ws.Cells.Item($row, 2).Interior.Color = [System.Drawing.Color]::LightYellow
                $ws.Cells.Item($row, 3).Interior.Color = [System.Drawing.Color]::LightYellow
                $ws.Cells.Item($row, 4).Interior.Color = [System.Drawing.Color]::LightYellow
                $ws.Cells.Item($row, 5).Interior.Color = [System.Drawing.Color]::LightYellow
                $ws.Cells.Item($row, 6).Interior.Color = [System.Drawing.Color]::LightYellow
                $ws.Cells.Item($row, 7).Interior.Color = [System.Drawing.Color]::LightYellow
                $ws.Cells.Item($row, 8).Interior.Color = [System.Drawing.Color]::LightYellow
            }
            # WHITE items (baseline) don't need color coding - they remain white
            $row++
        }
        
        # Save the Excel file
        $excel.Save()
        $excel.Dispose()
        
        Write-Host "Analysis complete! Results saved to: $OutputPath" -ForegroundColor Green
    } catch {
        Write-Error "Failed to create Excel output: $($_.Exception.Message)"
        # Fallback to CSV
        $csvPath = $OutputPath -replace '\.xlsx$', '.csv'
        $AllResults | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "Results saved to CSV: $csvPath" -ForegroundColor Yellow
    }
}

$redCount = ($AllResults | Where-Object { $_.Status -eq 'RED' }).Count
$yellowCount = ($AllResults | Where-Object { $_.Status -eq 'YELLOW' }).Count
$whiteCount = ($AllResults | Where-Object { $_.Status -eq 'WHITE' }).Count

Write-Host "Total items analyzed: $($AllResults.Count)" -ForegroundColor Cyan
Write-Host "Suspicious items (RED): $redCount" -ForegroundColor Red
Write-Host "After-market items (YELLOW): $yellowCount" -ForegroundColor Yellow
Write-Host "Baseline Windows items (WHITE): $whiteCount" -ForegroundColor White

Write-Host "Analysis complete!" -ForegroundColor Green

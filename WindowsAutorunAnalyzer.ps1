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
        $Command -match "C:\\Users\\.*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" -or
        $Command -match "^%windir%\\" -or
        $Command -match "^%SystemRoot%\\" -or
        $Command -match "^%windir%\\system32\\" -or
        $Command -match "^%SystemRoot%\\System32\\" -or
        $Command -match "explorer\\.exe" -or
        $Command -match "userinit\\.exe" -or
        $Command -match "sihost\\.exe" -or
        $Command -match "ShellAppRuntime\\.exe" -or
        $Command -match "SystemPropertiesPerformance\\.exe" -or
        $Command -match "rundll32\\.exe" -or
        $Command -match "compattelrunner\\.exe" -or
        $Command -match "sc\\.exe" -or
        $Command -match "sdbinst\\.exe" -or
        $Command -match "AppHostRegistrationVerifier\\.exe" -or
        $Command -match "dstokenclean\\.exe" -or
        $Command -match "UCPDMgr\\.exe" -or
        $Command -match "bcdboot\\.exe" -or
        $Command -match "wsqmcons\\.exe" -or
        $Command -match "defrag\\.exe" -or
        $Command -match "devicecensus\\.exe" -or
        $Command -match "UCConfigTask\\.exe" -or
        $Command -match "directxdatabaseupdater\\.exe" -or
        $Command -match "dxgiadaptercache\\.exe" -or
        $Command -match "cleanmgr\\.exe" -or
        $Command -match "disksnapshot\\.exe" -or
        $Command -match "BthUdTask\\.exe" -or
        $Command -match "Wscript\\.exe" -or
        $Command -match "OneDriveStandaloneUpdater\\.exe" -or
        $Command -match "OneDriveLauncher\\.exe" -or
        $Command -match "OneDrive\\.exe" -or
        $Command -match "AdobeARM\\.exe" -or
        $Command -match "BraveUpdate\\.exe" -or
        $Command -match "MicrosoftEdgeUpdate\\.exe" -or
        $Command -match "CheckStatus\\.bat" -or
        $Command -match "IntelSoftwareAssetManagerService\\.exe" -or
        $Command -match "iumsvc\\.exe" -or
        $Command -match "default-browser-agent\\.exe" -or
        $Command -match "updater\\.exe" -or
        $Command -match "ActionsServer\\.exe" -or
        $Command -match "OfficeC2RClient\\.exe" -or
        $Command -match "opushutil\\.exe" -or
        $Command -match "sdxhelper\\.exe" -or
        $Command -match "operfmon\\.exe" -or
        $Command -match "officesvcmgr\\.exe" -or
        $Command -match "BackgroundDownload\\.exe" -or
        $Command -match "SupportAssistInstaller\\.exe" -or
        $Command -match "Zoom\\.exe" -or
        # Check for Windows registry entries that should be baseline
        # SECURITY FIX: Use strict GUID format validation to prevent bypass
        $Command -match "^\{[A-Fa-f0-9]{8}-([A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}\}$" -or  # Proper GUID format only
        # Only allow specific known Windows registry values (not arbitrary numbers)
        ($Command -match "^[0-1]$" -and $_.Name -match "^(Enabled|Disabled|Hidden|Show)") -or  # Boolean-like registry values
        # Scientific notation for specific Windows timestamp values only
        $Command -match "^[0-9]+\\.[0-9]+E\\+1[1-2]$" -or  # Windows file times (limited to reasonable range)
        # Specific known Windows configuration values
        $Command -match "^(no|yes)$" -or  # Explicit yes/no values
        $Command -match "^0 0 0$" -or  # RGB color values
        $Command -match "^(2147484203|2147483648)$") {  # Known Windows DWORD values
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
    
    # Check for RMM (Remote Monitoring and Management) software
    $rmmPatterns = @(
        "teamviewer", "anydesk", "logmein", "gotomypc", "splashtop", "connectwise", "kaseya", "n-able", "continuum",
        "solarwinds", "pulseway", "aem", "ninja", "atera", "superops", "syncro", "barracuda", "datto",
        "screenconnect", "bomgar", "beyondtrust", "remoteutilities", "ultravnc", "tightvnc", "realvnc",
        "chrome remote", "microsoft remote desktop", "rdp", "remote desktop", "vnc", "radmin", "ammyy",
        "supremo", "rustdesk", "parsec", "chrome-remote-desktop", "remotix", "nomachine", "noip",
        "dynu", "no-ip", "duckdns", "freedns", "cloudflare", "ngrok", "tunnel", "proxy", "vpn"
    )
    
    foreach ($pattern in $rmmPatterns) {
        if ($Command -match $pattern -or $Path -match $pattern) {
            $suspicious = $true
            if ($reason) { $reason += "; " }
            $reason += "RMM/Remote Desktop software detected"
            break
        }
    }
    
    return @{
        IsSuspicious = $suspicious
        IsBaseline = $isBaseline
        Reason = $reason
    }
}

# Function to get file information including publisher, hashes, and timestamp
function Get-FileInfo {
    param($FilePath)
    
    $result = @{
        Publisher = ""
        ImagePath = ""
        MD5Hash = ""
        SHA1Hash = ""
        SHA256Hash = ""
        Timestamp = ""
        VerifiedSigner = $false
    }
    
    try {
        # Clean up the file path (remove quotes and arguments)
        $cleanPath = $FilePath -replace '^"([^"]+)".*$', '$1'
        $cleanPath = $cleanPath -split ' ' | Select-Object -First 1
        
        if (Test-Path $cleanPath -ErrorAction SilentlyContinue) {
            $fileInfo = Get-Item $cleanPath -ErrorAction SilentlyContinue
            if ($fileInfo) {
                $result.ImagePath = $fileInfo.FullName
                $result.Timestamp = $fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                
                # Get file hashes
                try {
                    $md5 = Get-FileHash -Path $cleanPath -Algorithm MD5 -ErrorAction SilentlyContinue
                    $sha1 = Get-FileHash -Path $cleanPath -Algorithm SHA1 -ErrorAction SilentlyContinue
                    $sha256 = Get-FileHash -Path $cleanPath -Algorithm SHA256 -ErrorAction SilentlyContinue
                    
                    if ($md5) { $result.MD5Hash = $md5.Hash }
                    if ($sha1) { $result.SHA1Hash = $sha1.Hash }
                    if ($sha256) { $result.SHA256Hash = $sha256.Hash }
                } catch {
                    # Hash calculation failed
                }
                
                # Get digital signature information
                try {
                    $signature = Get-AuthenticodeSignature -FilePath $cleanPath -ErrorAction SilentlyContinue
                    if ($signature -and $signature.Status -eq "Valid") {
                        $result.VerifiedSigner = $true
                        $result.Publisher = $signature.SignerCertificate.Subject
                        # Extract just the CN (Common Name) from the subject
                        if ($result.Publisher -match "CN=([^,]+)") {
                            $result.Publisher = $matches[1]
                        }
                    } elseif ($signature -and $signature.Status -ne "NotSigned") {
                        $result.Publisher = "Invalid Signature"
                    }
                } catch {
                    # Signature check failed
                }
            }
        }
    } catch {
        # File info extraction failed
    }
    
    return $result
}

# Function to sanitize data for CSV export (prevent formula injection)
function Protect-CsvValue {
    param([string]$Value)

    if ([string]::IsNullOrEmpty($Value)) {
        return $Value
    }

    # SECURITY FIX: Prevent CSV injection attacks
    # If value starts with =, +, -, @, or tab, prefix with single quote
    if ($Value -match "^[=+\-@`t]") {
        return "'" + $Value
    }

    # Also protect against pipe character which can be dangerous in some contexts
    if ($Value.StartsWith("|")) {
        return "'" + $Value
    }

    return $Value
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
                        $fileInfo = Get-FileInfo -FilePath $_.Value
                        $autoruns += [PSCustomObject]@{
                            Status = $status
                            User = Protect-CsvValue $Username
                            Type = "Registry"
                            Location = Protect-CsvValue $regPath
                            Name = Protect-CsvValue $_.Name
                            Command = Protect-CsvValue $_.Value
                            Publisher = Protect-CsvValue $fileInfo.Publisher
                            ImagePath = Protect-CsvValue $fileInfo.ImagePath
                            MD5Hash = $fileInfo.MD5Hash
                            SHA1Hash = $fileInfo.SHA1Hash
                            SHA256Hash = $fileInfo.SHA256Hash
                            Timestamp = $fileInfo.Timestamp
                            VerifiedSigner = $fileInfo.VerifiedSigner
                            IsSuspicious = $suspicious.IsSuspicious
                            IsBaseline = $suspicious.IsBaseline
                            Reason = Protect-CsvValue $suspicious.Reason
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
                    $fileInfo = Get-FileInfo -FilePath $_.FullName
                    $autoruns += [PSCustomObject]@{
                        Status = $status
                        User = Protect-CsvValue $Username
                        Type = "Startup Folder"
                        Location = Protect-CsvValue $startupPath
                        Name = Protect-CsvValue $_.Name
                        Command = Protect-CsvValue $_.FullName
                        Publisher = Protect-CsvValue $fileInfo.Publisher
                        ImagePath = Protect-CsvValue $fileInfo.ImagePath
                        MD5Hash = $fileInfo.MD5Hash
                        SHA1Hash = $fileInfo.SHA1Hash
                        SHA256Hash = $fileInfo.SHA256Hash
                        Timestamp = $fileInfo.Timestamp
                        VerifiedSigner = $fileInfo.VerifiedSigner
                        IsSuspicious = $suspicious.IsSuspicious
                        IsBaseline = $suspicious.IsBaseline
                        Reason = Protect-CsvValue $suspicious.Reason
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
                    $fileInfo = Get-FileInfo -FilePath $action.Execute
                    $tasks += [PSCustomObject]@{
                        Status = $status
                        User = "SYSTEM"
                        Type = "Scheduled Task"
                        Location = Protect-CsvValue $task.TaskPath
                        Name = Protect-CsvValue $task.TaskName
                        Command = Protect-CsvValue $action.Execute
                        Arguments = Protect-CsvValue $action.Arguments
                        Publisher = Protect-CsvValue $fileInfo.Publisher
                        ImagePath = Protect-CsvValue $fileInfo.ImagePath
                        MD5Hash = $fileInfo.MD5Hash
                        SHA1Hash = $fileInfo.SHA1Hash
                        SHA256Hash = $fileInfo.SHA256Hash
                        Timestamp = $fileInfo.Timestamp
                        VerifiedSigner = $fileInfo.VerifiedSigner
                        IsSuspicious = $suspicious.IsSuspicious
                        IsBaseline = $suspicious.IsBaseline
                        Reason = Protect-CsvValue $suspicious.Reason
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
                $fileInfo = Get-FileInfo -FilePath $service.PathName
                $services += [PSCustomObject]@{
                    Status = $status
                    User = "SYSTEM"
                    Type = "Service"
                    Location = "Services"
                    Name = Protect-CsvValue $service.Name
                    Command = Protect-CsvValue $service.PathName
                    StartMode = $service.StartMode
                    State = $service.State
                    Publisher = Protect-CsvValue $fileInfo.Publisher
                    ImagePath = Protect-CsvValue $fileInfo.ImagePath
                    MD5Hash = $fileInfo.MD5Hash
                    SHA1Hash = $fileInfo.SHA1Hash
                    SHA256Hash = $fileInfo.SHA256Hash
                    Timestamp = $fileInfo.Timestamp
                    VerifiedSigner = $fileInfo.VerifiedSigner
                    IsSuspicious = $suspicious.IsSuspicious
                    IsBaseline = $suspicious.IsBaseline
                    Reason = Protect-CsvValue $suspicious.Reason
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
                        $fileInfo = Get-FileInfo -FilePath $logonScript.UserInitMprLogonScript
                        $scripts += [PSCustomObject]@{
                            Status = $status
                            User = Protect-CsvValue $profile.Username
                            Type = "Logon Script"
                            Location = Protect-CsvValue $logonScriptPath
                            Name = "UserInitMprLogonScript"
                            Command = Protect-CsvValue $logonScript.UserInitMprLogonScript
                            Publisher = Protect-CsvValue $fileInfo.Publisher
                            ImagePath = Protect-CsvValue $fileInfo.ImagePath
                            MD5Hash = $fileInfo.MD5Hash
                            SHA1Hash = $fileInfo.SHA1Hash
                            SHA256Hash = $fileInfo.SHA256Hash
                            Timestamp = $fileInfo.Timestamp
                            VerifiedSigner = $fileInfo.VerifiedSigner
                            IsSuspicious = $suspicious.IsSuspicious
                            IsBaseline = $suspicious.IsBaseline
                            Reason = Protect-CsvValue $suspicious.Reason
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

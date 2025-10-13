# Windows Autorun Analyzer - Universal Script
# Handles all deployment scenarios in a single script
# GitHub, Local, LAN Share, and Portable modes

param(
    [string]$Mode = "auto",  # auto, github, local, share, portable
    [string]$GitHubUrl = "https://raw.githubusercontent.com/monobrau/windows-autorun-analyzer/main/WindowsAutorunAnalyzer_Universal.ps1",
    [string]$SharePath = "\\server\share\WindowsAutorunAnalyzer.ps1",
    [string]$LocalPath = ".\WindowsAutorunAnalyzer.ps1",
    [string]$OutputPath = "C:\dev\AutorunAnalysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').xlsx",
    [switch]$Help
)

# Show help if requested
if ($Help) {
    Write-Host @"
Windows Autorun Analyzer - Universal Script
==========================================

This single script handles all deployment scenarios:
- GitHub download (with internet)
- Local execution (no internet)
- LAN share access (network deployment)
- Portable mode (no dependencies)

Usage:
  .\WindowsAutorunAnalyzer_Universal.ps1 [parameters]

Parameters:
  -Mode <string>        : auto, github, local, share, portable (default: auto)
  -GitHubUrl <string>   : GitHub raw URL for script download
  -SharePath <string>   : UNC path to script on LAN share
  -LocalPath <string>   : Local path to script file
  -OutputPath <string>  : Output path for analysis results
  -Help                 : Show this help message

Examples:
  # Auto-detect best method
  .\WindowsAutorunAnalyzer_Universal.ps1

  # Force GitHub download
  .\WindowsAutorunAnalyzer_Universal.ps1 -Mode github

  # Use local script
  .\WindowsAutorunAnalyzer_Universal.ps1 -Mode local

  # Use LAN share
  .\WindowsAutorunAnalyzer_Universal.ps1 -Mode share -SharePath "\\server\share\script.ps1"

  # Portable mode (no dependencies)
  .\WindowsAutorunAnalyzer_Universal.ps1 -Mode portable

"@
    exit 0
}

# Function to write status messages
function Write-Status {
    param($Message, $Color = "White")
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $Color
}

# Function to test internet connection
function Test-InternetConnection {
    try {
        $response = Invoke-WebRequest -Uri "https://www.google.com" -TimeoutSec 5 -UseBasicParsing
        return $true
    } catch {
        return $false
    }
}

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
    if (Test-Path $ProfilePath -ErrorAction SilentlyContinue) {
        $userRegPath = "HKU:\$SID"
        if (Test-Path $userRegPath -ErrorAction SilentlyContinue) {
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
            if (Test-Path $regPath -ErrorAction SilentlyContinue) {
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
                            User = $Username
                            Type = "Registry"
                            Location = $regPath
                            Name = $_.Name
                            Command = $_.Value
                            Publisher = $fileInfo.Publisher
                            ImagePath = $fileInfo.ImagePath
                            MD5Hash = $fileInfo.MD5Hash
                            SHA1Hash = $fileInfo.SHA1Hash
                            SHA256Hash = $fileInfo.SHA256Hash
                            Timestamp = $fileInfo.Timestamp
                            VerifiedSigner = $fileInfo.VerifiedSigner
                            IsSuspicious = $suspicious.IsSuspicious
                            IsBaseline = $suspicious.IsBaseline
                            Reason = $suspicious.Reason
                            Status = $status
                        }
                    }
                }
            }
        } catch {
            Write-Status "Could not access registry path: $regPath" "Yellow"
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
                        User = $Username
                        Type = "Startup Folder"
                        Location = $startupPath
                        Name = $_.Name
                        Command = $_.FullName
                        Publisher = $fileInfo.Publisher
                        ImagePath = $fileInfo.ImagePath
                        MD5Hash = $fileInfo.MD5Hash
                        SHA1Hash = $fileInfo.SHA1Hash
                        SHA256Hash = $fileInfo.SHA256Hash
                        Timestamp = $fileInfo.Timestamp
                        VerifiedSigner = $fileInfo.VerifiedSigner
                        IsSuspicious = $suspicious.IsSuspicious
                        IsBaseline = $suspicious.IsBaseline
                        Reason = $suspicious.Reason
                        Status = $status
                    }
                }
            }
        } catch {
            Write-Status "Could not access startup folder: $startupPath" "Yellow"
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
            $taskActions = $task.Actions
            
            foreach ($action in $taskActions) {
                if ($action.Execute) {
                    $suspicious = Test-SuspiciousItem -Path $action.Execute -Command $action.Execute
                    $status = if ($suspicious.IsSuspicious) { "RED" } elseif ($suspicious.IsBaseline) { "WHITE" } else { "YELLOW" }
                    $fileInfo = Get-FileInfo -FilePath $action.Execute
                    $tasks += [PSCustomObject]@{
                        User = "SYSTEM"
                        Type = "Scheduled Task"
                        Location = $task.TaskPath
                        Name = $task.TaskName
                        Command = $action.Execute
                        Arguments = $action.Arguments
                        Publisher = $fileInfo.Publisher
                        ImagePath = $fileInfo.ImagePath
                        MD5Hash = $fileInfo.MD5Hash
                        SHA1Hash = $fileInfo.SHA1Hash
                        SHA256Hash = $fileInfo.SHA256Hash
                        Timestamp = $fileInfo.Timestamp
                        VerifiedSigner = $fileInfo.VerifiedSigner
                        IsSuspicious = $suspicious.IsSuspicious
                        IsBaseline = $suspicious.IsBaseline
                        Reason = $suspicious.Reason
                        Status = $status
                    }
                }
            }
        }
    } catch {
        Write-Status "Could not enumerate scheduled tasks: $($_.Exception.Message)" "Yellow"
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
                    User = "SYSTEM"
                    Type = "Service"
                    Location = "Services"
                    Name = $service.Name
                    Command = $service.PathName
                    StartMode = $service.StartMode
                    State = $service.State
                    Publisher = $fileInfo.Publisher
                    ImagePath = $fileInfo.ImagePath
                    MD5Hash = $fileInfo.MD5Hash
                    SHA1Hash = $fileInfo.SHA1Hash
                    SHA256Hash = $fileInfo.SHA256Hash
                    Timestamp = $fileInfo.Timestamp
                    VerifiedSigner = $fileInfo.VerifiedSigner
                    IsSuspicious = $suspicious.IsSuspicious
                    IsBaseline = $suspicious.IsBaseline
                    Reason = $suspicious.Reason
                    Status = $status
                }
            }
        }
    } catch {
        Write-Status "Could not enumerate services: $($_.Exception.Message)" "Yellow"
    }
    
    return $services
}

# Function to analyze logon scripts
function Get-LogonScripts {
    $scripts = @()
    
    try {
        $userProfiles = Get-AllUserProfiles
        foreach ($profile in $userProfiles) {
            if ($profile.SID -and $profile.SID -ne "S-1-5-18" -and $profile.SID -ne "S-1-5-19" -and $profile.SID -ne "S-1-5-20") {
                $logonScriptPath = "HKU:\$($profile.SID)\Environment"
                if (Test-Path $logonScriptPath -ErrorAction SilentlyContinue) {
                    $logonScript = Get-ItemProperty -Path $logonScriptPath -Name "UserInitMprLogonScript" -ErrorAction SilentlyContinue
                    if ($logonScript -and $logonScript.UserInitMprLogonScript) {
                        $suspicious = Test-SuspiciousItem -Path $logonScript.UserInitMprLogonScript -Command $logonScript.UserInitMprLogonScript
                        $status = if ($suspicious.IsSuspicious) { "RED" } elseif ($suspicious.IsBaseline) { "WHITE" } else { "YELLOW" }
                        $fileInfo = Get-FileInfo -FilePath $logonScript.UserInitMprLogonScript
                        $scripts += [PSCustomObject]@{
                            User = $profile.Username
                            Type = "Logon Script"
                            Location = $logonScriptPath
                            Name = "UserInitMprLogonScript"
                            Command = $logonScript.UserInitMprLogonScript
                            Publisher = $fileInfo.Publisher
                            ImagePath = $fileInfo.ImagePath
                            MD5Hash = $fileInfo.MD5Hash
                            SHA1Hash = $fileInfo.SHA1Hash
                            SHA256Hash = $fileInfo.SHA256Hash
                            Timestamp = $fileInfo.Timestamp
                            VerifiedSigner = $fileInfo.VerifiedSigner
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
        Write-Status "Could not enumerate logon scripts: $($_.Exception.Message)" "Yellow"
    }
    
    return $scripts
}

# Function to perform the autorun analysis
function Start-AutorunAnalysis {
    param($OutputPath)
    
    Write-Status "Starting Windows Autorun Analysis..." "Green"
    Write-Status "Output will be saved to: $OutputPath" "Yellow"
    
    # Initialize results array
    $AllResults = @()
    
    # Get all user profiles
    $userProfiles = Get-AllUserProfiles
    Write-Status "Found $($userProfiles.Count) user profiles to analyze" "Cyan"
    
    # Analyze each user
    foreach ($profile in $userProfiles) {
        Write-Status "Analyzing user: $($profile.Username)" "Cyan"
        
        # Registry autoruns
        $registryAutoruns = Get-RegistryAutoruns -Username $profile.Username -ProfilePath $profile.ProfilePath -SID $profile.SID
        $AllResults += $registryAutoruns
        
        # Startup folder autoruns
        $startupAutoruns = Get-StartupFolderAutoruns -Username $profile.Username -ProfilePath $profile.ProfilePath
        $AllResults += $startupAutoruns
    }
    
    # Analyze system-wide items
    Write-Status "Analyzing system-wide items..." "Cyan"
    
    # Scheduled tasks
    $scheduledTasks = Get-ScheduledTasks
    $AllResults += $scheduledTasks
    
    # Services
    $services = Get-Services
    $AllResults += $services
    
    # Logon scripts
    $logonScripts = Get-LogonScripts
    $AllResults += $logonScripts
    
    # Create output
    Write-Status "Creating output..." "Green"
    
    # Try to import ImportExcel module
    $excelModuleLoaded = $false
    Write-Status "Attempting to load ImportExcel module..." "Cyan"
    try {
        Import-Module ImportExcel -ErrorAction SilentlyContinue
        $excelModuleLoaded = $true
        Write-Status "ImportExcel module loaded successfully" "Green"
    } catch {
        Write-Status "Standard import failed, trying alternative method..." "Yellow"
        # Try alternative import methods
        try {
            $modulePath = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\ImportExcel"
            Write-Status "Looking for module in: $modulePath" "Cyan"
            $latestVersion = Get-ChildItem $modulePath -Directory | Sort-Object Name -Descending | Select-Object -First 1
            if ($latestVersion) {
                Write-Status "Found version: $($latestVersion.Name)" "Cyan"
                Import-Module "$($latestVersion.FullName)\ImportExcel.psm1" -ErrorAction SilentlyContinue
                $excelModuleLoaded = $true
                Write-Status "ImportExcel module loaded from: $($latestVersion.FullName)" "Green"
            } else {
                Write-Status "No ImportExcel module found in $modulePath" "Yellow"
            }
        } catch {
            Write-Status "Alternative import also failed: $($_.Exception.Message)" "Red"
        }
    }
    
    # Try to use Export-Excel directly
    Write-Status "Attempting Excel export..." "Cyan"
    try {
        # Create Excel file with color coding
        Write-Status "Creating Excel file with color coding..." "Cyan"
        
        # First try to create the Excel file without PassThru
        Write-Status "Creating basic Excel file..." "Cyan"
        $AllResults | Export-Excel -Path $OutputPath -AutoSize -TableStyle Medium2
        
        # Check if file was created
        if (Test-Path $OutputPath) {
            Write-Status "Basic Excel file created successfully" "Green"
            
            # Now try to add color coding using COM object approach
            try {
                Write-Status "Adding color coding using COM object..." "Cyan"
                
                # Create Excel COM object
                $excel = New-Object -ComObject Excel.Application
                $excel.Visible = $false
                $excel.DisplayAlerts = $false
                
                # Open the existing Excel file
                $workbook = $excel.Workbooks.Open($OutputPath)
                $worksheet = $workbook.Worksheets.Item(1)
                
                # Add color coding
                $row = 2  # Start from row 2 (skip header)
                foreach ($result in $AllResults) {
                    if ($result.Status -eq "RED") {
                        $worksheet.Cells.Item($row, 1).Interior.Color = 255  # Light Red
                        $worksheet.Cells.Item($row, 2).Interior.Color = 255
                        $worksheet.Cells.Item($row, 3).Interior.Color = 255
                        $worksheet.Cells.Item($row, 4).Interior.Color = 255
                        $worksheet.Cells.Item($row, 5).Interior.Color = 255
                    } elseif ($result.Status -eq "YELLOW") {
                        $worksheet.Cells.Item($row, 1).Interior.Color = 65535  # Light Yellow
                        $worksheet.Cells.Item($row, 2).Interior.Color = 65535
                        $worksheet.Cells.Item($row, 3).Interior.Color = 65535
                        $worksheet.Cells.Item($row, 4).Interior.Color = 65535
                        $worksheet.Cells.Item($row, 5).Interior.Color = 65535
                    } elseif ($result.Status -eq "WHITE") {
                        $worksheet.Cells.Item($row, 1).Interior.Color = 16777215  # White
                        $worksheet.Cells.Item($row, 2).Interior.Color = 16777215
                        $worksheet.Cells.Item($row, 3).Interior.Color = 16777215
                        $worksheet.Cells.Item($row, 4).Interior.Color = 16777215
                        $worksheet.Cells.Item($row, 5).Interior.Color = 16777215
                    }
                    $row++
                }
                
                # Create Pivot Table for better analysis
                Write-Status "Creating pivot table for analysis..." "Cyan"
                try {
                    # Add a new worksheet for pivot table with safe name
                    $pivotWorksheet = $workbook.Worksheets.Add()
                    $pivotWorksheet.Name = "Analysis"
                    
                    # Add title
                    $pivotWorksheet.Cells.Item(1, 1) = "Windows Autorun Analysis Summary"
                    $pivotWorksheet.Cells.Item(1, 1).Font.Bold = $true
                    $pivotWorksheet.Cells.Item(1, 1).Font.Size = 14
                    
                    # Create pivot table using the data from the main worksheet
                    $dataRange = $worksheet.UsedRange
                    $pivotCache = $workbook.PivotCaches().Create(1, $dataRange, 1)  # xlDatabase = 1
                    $pivotTable = $pivotCache.CreatePivotTable($pivotWorksheet.Cells.Item(3, 1), "AutorunAnalysisPivot", $true, $true)
                    
                    # Configure pivot table fields
                    $pivotTable.PivotFields("Status").Orientation = 1  # xlRowField = 1
                    $pivotTable.PivotFields("Type").Orientation = 1    # xlRowField = 1
                    $pivotTable.PivotFields("User").Orientation = 1    # xlRowField = 1
                    
                    # Add count of items
                    $pivotTable.PivotFields("Name").Orientation = 4    # xlDataField = 4
                    $pivotTable.PivotFields("Count of Name").Function = -4112  # xlCount = -4112
                    
                    # Add Publisher analysis
                    $pivotTable.PivotFields("Publisher").Orientation = 2  # xlColumnField = 2
                    
                    # Format the pivot table
                    $pivotTable.TableStyle2 = "PivotStyleMedium2"
                    
                    # Add summary statistics above the pivot table
                    $summaryRow = 1
                    $pivotWorksheet.Cells.Item($summaryRow, 3) = "Total Items: $($AllResults.Count)"
                    $summaryRow++
                    $pivotWorksheet.Cells.Item($summaryRow, 3) = "Suspicious (RED): $(($AllResults | Where-Object { $_.Status -eq 'RED' }).Count)"
                    $summaryRow++
                    $pivotWorksheet.Cells.Item($summaryRow, 3) = "After-market (YELLOW): $(($AllResults | Where-Object { $_.Status -eq 'YELLOW' }).Count)"
                    $summaryRow++
                    $pivotWorksheet.Cells.Item($summaryRow, 3) = "Baseline (WHITE): $(($AllResults | Where-Object { $_.Status -eq 'WHITE' }).Count)"
                    
                    # Auto-fit columns
                    $pivotWorksheet.UsedRange.Columns.AutoFit()
                    
                    Write-Status "Pivot table created successfully" "Green"
                } catch {
                    Write-Status "Pivot table creation failed, creating simple summary: $($_.Exception.Message)" "Yellow"
                    
                    # Fallback to simple summary if pivot table fails
                    try {
                        # Add a new worksheet for summary with safe name
                        $pivotWorksheet = $workbook.Worksheets.Add()
                        $pivotWorksheet.Name = "Summary"
                        
                        # Add title
                        $pivotWorksheet.Cells.Item(1, 1) = "Windows Autorun Analysis Summary"
                        $pivotWorksheet.Cells.Item(1, 1).Font.Bold = $true
                        $pivotWorksheet.Cells.Item(1, 1).Font.Size = 14
                        
                        # Add summary statistics
                        $row = 3
                        $pivotWorksheet.Cells.Item($row, 1) = "Total Items:"
                        $pivotWorksheet.Cells.Item($row, 2) = $AllResults.Count
                        $row++
                        
                        $pivotWorksheet.Cells.Item($row, 1) = "Suspicious (RED):"
                        $pivotWorksheet.Cells.Item($row, 2) = ($AllResults | Where-Object { $_.Status -eq 'RED' }).Count
                        $row++
                        
                        $pivotWorksheet.Cells.Item($row, 1) = "After-market (YELLOW):"
                        $pivotWorksheet.Cells.Item($row, 2) = ($AllResults | Where-Object { $_.Status -eq 'YELLOW' }).Count
                        $row++
                        
                        $pivotWorksheet.Cells.Item($row, 1) = "Baseline (WHITE):"
                        $pivotWorksheet.Cells.Item($row, 2) = ($AllResults | Where-Object { $_.Status -eq 'WHITE' }).Count
                        $row += 2
                        
                        # Add breakdown by type
                        $pivotWorksheet.Cells.Item($row, 1) = "Breakdown by Type:"
                        $pivotWorksheet.Cells.Item($row, 1).Font.Bold = $true
                        $row++
                        
                        $typeGroups = $AllResults | Group-Object Type | Sort-Object Count -Descending
                        foreach ($group in $typeGroups) {
                            $pivotWorksheet.Cells.Item($row, 1) = $group.Name
                            $pivotWorksheet.Cells.Item($row, 2) = $group.Count
                            $row++
                        }
                        $row += 2
                        
                        # Add breakdown by user
                        $pivotWorksheet.Cells.Item($row, 1) = "Breakdown by User:"
                        $pivotWorksheet.Cells.Item($row, 1).Font.Bold = $true
                        $row++
                        
                        $userGroups = $AllResults | Group-Object User | Sort-Object Count -Descending
                        foreach ($group in $userGroups) {
                            $pivotWorksheet.Cells.Item($row, 1) = $group.Name
                            $pivotWorksheet.Cells.Item($row, 2) = $group.Count
                            $row++
                        }
                        
                        # Auto-fit columns
                        $pivotWorksheet.UsedRange.Columns.AutoFit()
                        
                        Write-Status "Simple summary created successfully" "Green"
                    } catch {
                        Write-Status "Summary creation also failed: $($_.Exception.Message)" "Red"
                    }
                }
                
                # Save and close
                $workbook.Save()
                $workbook.Close()
                $excel.Quit()
                [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
                
                Write-Status "Excel file with color coding created successfully: $OutputPath" "Green"
            } catch {
                Write-Status "Color coding failed, but basic Excel file was created: $($_.Exception.Message)" "Yellow"
                Write-Status "Excel file saved without color coding: $OutputPath" "Green"
                
                # Clean up COM objects if they exist
                try {
                    if ($workbook) { $workbook.Close() }
                    if ($excel) { 
                        $excel.Quit()
                        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
                    }
                } catch {
                    # Ignore cleanup errors
                }
            }
        } else {
            Write-Status "Basic Excel file creation failed, falling back to CSV" "Yellow"
            $csvPath = $OutputPath -replace '\.xlsx$', '.csv'
            $AllResults | Export-Csv -Path $csvPath -NoTypeInformation
            Write-Status "Results saved to CSV: $csvPath" "Yellow"
        }
    } catch {
        Write-Status "Excel export failed, falling back to CSV: $($_.Exception.Message)" "Yellow"
    $csvPath = $OutputPath -replace '\.xlsx$', '.csv'
    $AllResults | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Status "Results saved to CSV: $csvPath" "Yellow"
    }
    
    # Calculate counts
    $redCount = ($AllResults | Where-Object { $_.Status -eq 'RED' }).Count
    $yellowCount = ($AllResults | Where-Object { $_.Status -eq 'YELLOW' }).Count
    $whiteCount = ($AllResults | Where-Object { $_.Status -eq 'WHITE' }).Count
    
    Write-Status "Total items analyzed: $($AllResults.Count)" "Cyan"
    Write-Status "Suspicious items (RED): $redCount" "Red"
    Write-Status "After-market items (YELLOW): $yellowCount" "Yellow"
    Write-Status "Baseline Windows items (WHITE): $whiteCount" "White"
    
    Write-Status "Analysis complete! Results saved to: $csvPath" "Green"
    
    return $csvPath
}

# Main execution logic
Write-Status "Windows Autorun Analyzer - Universal Script" "Cyan"
Write-Status "Mode: $Mode" "Cyan"

# Create output directory if it doesn't exist
$outputDir = Split-Path $OutputPath -Parent
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$success = $false
$scriptPath = ""

switch ($Mode.ToLower()) {
    "github" {
        Write-Status "GitHub mode: Downloading script..." "Yellow"
        try {
            $scriptContent = Invoke-WebRequest -Uri $GitHubUrl -UseBasicParsing
            $scriptPath = Join-Path $outputDir "WindowsAutorunAnalyzer_Downloaded.ps1"
            $scriptContent.Content | Out-File -FilePath $scriptPath -Encoding UTF8
            Write-Status "Script downloaded successfully" "Green"
            $success = $true
        } catch {
            Write-Status "Failed to download from GitHub: $($_.Exception.Message)" "Red"
        }
    }
    "local" {
        Write-Status "Local mode: Using local script..." "Yellow"
        if (Test-Path $LocalPath) {
            $scriptPath = $LocalPath
            $success = $true
        } else {
            Write-Status "Local script not found: $LocalPath" "Red"
        }
    }
    "share" {
        Write-Status "Share mode: Copying from LAN share..." "Yellow"
        try {
            if (Test-Path $SharePath) {
                $scriptPath = Join-Path $outputDir "WindowsAutorunAnalyzer_FromShare.ps1"
                Copy-Item -Path $SharePath -Destination $scriptPath -Force
                Write-Status "Script copied from share successfully" "Green"
                $success = $true
            } else {
                Write-Status "Share not accessible: $SharePath" "Red"
            }
        } catch {
            Write-Status "Failed to copy from share: $($_.Exception.Message)" "Red"
        }
    }
    "portable" {
        Write-Status "Portable mode: Running embedded analysis..." "Green"
        $csvPath = Start-AutorunAnalysis -OutputPath $OutputPath
        $success = $true
    }
    "auto" {
        Write-Status "Auto mode: Detecting best method..." "Yellow"
        
        # Check if we're already running from GitHub (prevent infinite loop)
        $currentScriptPath = $MyInvocation.PSCommandPath
        if ($currentScriptPath -and $currentScriptPath -match "WindowsAutorunAnalyzer.*\.ps1$") {
            Write-Status "Already running from downloaded script, using portable mode..." "Green"
            $csvPath = Start-AutorunAnalysis -OutputPath $OutputPath
            $success = $true
        } else {
            # Try GitHub first if internet is available
            if (Test-InternetConnection) {
                Write-Status "Internet detected, trying GitHub..." "Green"
                try {
                    $scriptContent = Invoke-WebRequest -Uri $GitHubUrl -UseBasicParsing
                    $scriptPath = Join-Path $outputDir "WindowsAutorunAnalyzer_Auto.ps1"
                    $scriptContent.Content | Out-File -FilePath $scriptPath -Encoding UTF8
                    Write-Status "Script downloaded from GitHub" "Green"
                    $success = $true
                } catch {
                    Write-Status "GitHub failed, trying local..." "Yellow"
                    if (Test-Path $LocalPath) {
                        $scriptPath = $LocalPath
                        $success = $true
                    } else {
                        Write-Status "Local not found, using portable mode..." "Yellow"
                        $csvPath = Start-AutorunAnalysis -OutputPath $OutputPath
                        $success = $true
                    }
                }
            } else {
                Write-Status "No internet, trying local..." "Yellow"
                if (Test-Path $LocalPath) {
                    $scriptPath = $LocalPath
                    $success = $true
                } else {
                    Write-Status "Local not found, using portable mode..." "Yellow"
                    $csvPath = Start-AutorunAnalysis -OutputPath $OutputPath
                    $success = $true
                }
            }
        }
    }
    default {
        Write-Status "Invalid mode: $Mode" "Red"
        Write-Status "Use: auto, github, local, share, or portable" "Yellow"
        exit 1
    }
}

# Execute the script if we have one
if ($success -and $scriptPath -and $Mode -ne "local") {
    Write-Status "Executing Windows Autorun Analyzer..." "Green"
    try {
        & $scriptPath -OutputPath $OutputPath
        Write-Status "Analysis completed successfully!" "Green"
    } catch {
        Write-Status "Error executing script: $($_.Exception.Message)" "Red"
        Write-Status "Falling back to portable mode..." "Yellow"
        Start-AutorunAnalysis -OutputPath $OutputPath
    }
} else {
    if ($Mode -eq "local") {
        Write-Status "Using built-in analysis engine..." "Green"
    } else {
    Write-Status "Failed to obtain script, using portable mode..." "Yellow"
    }
    Start-AutorunAnalysis -OutputPath $OutputPath
}

Write-Status "Universal script completed!" "Cyan"

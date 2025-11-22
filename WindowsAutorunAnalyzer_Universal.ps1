# Windows Autorun Analyzer - Universal Script
# Handles all deployment scenarios in a single script
# GitHub, Local, LAN Share, and Portable modes

param(
    [string]$Mode = "auto",  # auto, github, local, share, portable
    [string]$GitHubUrl = "https://raw.githubusercontent.com/monobrau/windows-autorun-analyzer/main/WindowsAutorunAnalyzer_Universal.ps1",
    [string]$SharePath = "\\server\share\WindowsAutorunAnalyzer.ps1",
    [string]$LocalPath = ".\WindowsAutorunAnalyzer.ps1",
    [string]$OutputPath = "C:\dev\AutorunAnalysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').xlsx",
    [switch]$EnableVirusTotal,  # Enable VirusTotal hash lookups
    [string]$VTApiKey = "",     # VirusTotal API key (free tier: 4/min, 500/day)
    [string]$VTCachePath = ".\vt_cache.json",  # Local cache file for VT results
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
  -EnableVirusTotal     : Enable VirusTotal hash lookups (requires API key)
  -VTApiKey <string>    : VirusTotal API key (free tier: 4/min, 500/day)
  -VTCachePath <string> : Path to VT cache file (default: .\vt_cache.json)
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

  # With VirusTotal checking (RED/YELLOW items only)
  .\WindowsAutorunAnalyzer_Universal.ps1 -EnableVirusTotal -VTApiKey "your-api-key-here"

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
    # SECURITY FIX: Improved network validation with proper error handling
    try {
        # Use Microsoft endpoint instead of Google for privacy
        # Verify SSL/TLS certificate and check response code
        $response = Invoke-WebRequest -Uri "https://www.microsoft.com" `
            -TimeoutSec 10 `
            -UseBasicParsing `
            -ErrorAction Stop `
            -MaximumRedirection 0

        # Verify we got a valid response
        if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 301 -or $response.StatusCode -eq 302) {
            return $true
        }

        Write-Verbose "Internet check failed: Unexpected status code $($response.StatusCode)"
        return $false
    } catch [System.Net.WebException] {
        Write-Verbose "Internet check failed: Network error - $($_.Exception.Message)"
        return $false
    } catch [System.Security.Authentication.AuthenticationException] {
        Write-Verbose "Internet check failed: SSL/TLS validation error - $($_.Exception.Message)"
        return $false
    } catch {
        Write-Verbose "Internet check failed: $($_.Exception.Message)"
        return $false
    }
}

# Function to validate downloaded script integrity
function Test-ScriptIntegrity {
    param(
        [string]$ScriptPath,
        [switch]$RequireSignature
    )

    # SECURITY FIX: Validate scripts before execution
    if (-not (Test-Path $ScriptPath)) {
        Write-Status "Script not found: $ScriptPath" "Red"
        return $false
    }

    try {
        # Check file size (prevent extremely large files)
        $fileSize = (Get-Item $ScriptPath).Length
        if ($fileSize -gt 50MB) {
            Write-Status "Script file too large ($($fileSize/1MB) MB). Maximum: 50MB" "Red"
            return $false
        }

        if ($fileSize -eq 0) {
            Write-Status "Script file is empty" "Red"
            return $false
        }

        # Validate it's actually a PowerShell script
        $content = Get-Content $ScriptPath -First 5 -ErrorAction Stop
        $looksLikePS = $false
        foreach ($line in $content) {
            if ($line -match "^#|^param|^function|^\$|^Get-|^Set-|^Invoke-") {
                $looksLikePS = $true
                break
            }
        }

        if (-not $looksLikePS) {
            Write-Status "File doesn't appear to be a PowerShell script" "Yellow"
            # Don't fail, but warn
        }

        # Check digital signature if required
        if ($RequireSignature) {
            $signature = Get-AuthenticodeSignature -FilePath $ScriptPath -ErrorAction Stop
            if ($signature.Status -ne 'Valid') {
                Write-Status "Script signature invalid or missing: $($signature.Status)" "Red"
                Write-Status "Signer: $($signature.SignerCertificate.Subject)" "Yellow"
                return $false
            }
            Write-Status "Script signature valid: $($signature.SignerCertificate.Subject)" "Green"
        }

        Write-Verbose "Script integrity check passed for: $ScriptPath"
        return $true

    } catch {
        Write-Status "Script integrity check failed: $($_.Exception.Message)" "Red"
        return $false
    }
}

# Function to load VirusTotal cache
function Get-VTCache {
    param([string]$CachePath)

    if (Test-Path $CachePath) {
        try {
            $cache = Get-Content $CachePath -Raw | ConvertFrom-Json
            return $cache
        } catch {
            Write-Verbose "Failed to load VT cache: $($_.Exception.Message)"
            return @{}
        }
    }
    return @{}
}

# Function to save VirusTotal cache
function Save-VTCache {
    param(
        [hashtable]$Cache,
        [string]$CachePath
    )

    try {
        $Cache | ConvertTo-Json -Depth 10 | Out-File -FilePath $CachePath -Encoding UTF8
        Write-Verbose "VT cache saved: $CachePath"
    } catch {
        Write-Verbose "Failed to save VT cache: $($_.Exception.Message)"
    }
}

# Function to query VirusTotal for file hash
function Get-VirusTotalReport {
    param(
        [string]$SHA256Hash,
        [string]$ApiKey,
        [hashtable]$Cache
    )

    # Return cached result if available
    if ($Cache.ContainsKey($SHA256Hash)) {
        Write-Verbose "VT cache hit for $SHA256Hash"
        return $Cache[$SHA256Hash]
    }

    if ([string]::IsNullOrEmpty($SHA256Hash) -or $SHA256Hash.Length -ne 64) {
        return @{
            Detections = "N/A"
            Permalink = ""
            Reputation = "Unknown"
            Error = "Invalid hash"
        }
    }

    try {
        $url = "https://www.virustotal.com/api/v3/files/$SHA256Hash"
        $headers = @{
            "x-apikey" = $ApiKey
        }

        Write-Verbose "Querying VT for $SHA256Hash"
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers -ErrorAction Stop

        $malicious = $response.data.attributes.last_analysis_stats.malicious
        $total = $response.data.attributes.last_analysis_stats.malicious +
                 $response.data.attributes.last_analysis_stats.suspicious +
                 $response.data.attributes.last_analysis_stats.undetected +
                 $response.data.attributes.last_analysis_stats.harmless

        $reputation = if ($malicious -gt 5) { "Malicious" }
                     elseif ($malicious -gt 0) { "Suspicious" }
                     else { "Clean" }

        $result = @{
            Detections = "$malicious/$total"
            Permalink = "https://www.virustotal.com/gui/file/$SHA256Hash"
            Reputation = $reputation
            Error = $null
        }

        # Cache the result
        $Cache[$SHA256Hash] = $result

        return $result

    } catch {
        $statusCode = $_.Exception.Response.StatusCode.Value__

        if ($statusCode -eq 404) {
            # File not found in VT database
            $result = @{
                Detections = "0/0"
                Permalink = ""
                Reputation = "Not Found"
                Error = "Not in VT database"
            }
        } elseif ($statusCode -eq 429) {
            # Rate limit exceeded
            $result = @{
                Detections = "N/A"
                Permalink = ""
                Reputation = "Rate Limited"
                Error = "API rate limit exceeded"
            }
        } else {
            $result = @{
                Detections = "N/A"
                Permalink = ""
                Reputation = "Error"
                Error = $_.Exception.Message
            }
        }

        # Don't cache errors (except 404)
        if ($statusCode -eq 404) {
            $Cache[$SHA256Hash] = $result
        }

        return $result
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
    
    # Check for .lnk files (shortcuts) - can be used for persistence
    if ($Command -match "\.lnk$" -or $Path -match "\.lnk$") {
        if ($reason) { $reason += "; " }
        $reason += "Shortcut file (.lnk) detected"
        
        # Check if it's in a suspicious location
        if ($Command -match "temp|tmp|downloads|desktop|documents|public|appdata\\local\\temp|appdata\\roaming" -or 
            $Path -match "temp|tmp|downloads|desktop|documents|public|appdata\\local\\temp|appdata\\roaming") {
            $suspicious = $true
            if ($reason) { $reason += "; " }
            $reason += "Shortcut in suspicious location"
        }
    }
    
    # Check for RMM (Remote Monitoring and Management) software - be more specific to avoid false positives
    $rmmPatterns = @(
        "teamviewer", "anydesk", "logmein", "gotomypc", "splashtop", "connectwise", "kaseya", "n-able", "continuum",
        "solarwinds", "pulseway", "aem", "ninja", "atera", "superops", "syncro", "barracuda", "datto",
        "screenconnect", "bomgar", "beyondtrust", "remoteutilities", "ultravnc", "tightvnc", "realvnc",
        "chrome-remote-desktop", "radmin", "ammyy", "supremo", "rustdesk", "parsec", "remotix", "nomachine",
        "noip", "dynu", "no-ip", "duckdns", "freedns", "cloudflare", "ngrok", "tunnel", "proxy", "vpn"
    )
    
    # Check for suspicious remote access patterns (more specific)
    $suspiciousRemotePatterns = @(
        "chrome remote", "mstsc", "rdp", "vnc", "vpn"
    )
    
    foreach ($pattern in $rmmPatterns) {
        if ($Command -match $pattern -or $Path -match $pattern) {
            $suspicious = $true
            if ($reason) { $reason += "; " }
            $reason += "RMM/Remote Desktop software detected"
            break
        }
    }
    
    # Check for remote access tools by publisher
    $rmmPublishers = @(
        "teamviewer", "anydesk", "logmein", "splashtop", "connectwise", "kaseya", "n-able", "continuum",
        "solarwinds", "pulseway", "aem", "ninja", "atera", "superops", "syncro", "barracuda", "datto",
        "beyondtrust", "ultravnc", "tightvnc", "realvnc", "radmin", "ammyy", "supremo", "rustdesk",
        "parsec", "remotix", "nomachine", "noip", "dynu", "duckdns", "freedns", "cloudflare", "screenconnect"
    )
    
    # This will be checked later when we have publisher info
    $rmmPublisherDetected = $false
    foreach ($publisher in $rmmPublishers) {
        if ($Command -match $publisher -or $Path -match $publisher) {
            $rmmPublisherDetected = $true
            break
        }
    }
    
    return @{
        IsSuspicious = $suspicious
        IsBaseline = $isBaseline
        Reason = $reason
        RmmPublisherDetected = $rmmPublisherDetected
    }
}

# Function to get .lnk file target information
function Get-LnkTarget {
    param($LnkPath)
    
    $result = @{
        TargetPath = ""
        TargetArguments = ""
        TargetWorkingDirectory = ""
        IsLnkFile = $false
    }
    
    try {
        if (Test-Path $LnkPath -ErrorAction SilentlyContinue) {
            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut($LnkPath)
            
            $result.IsLnkFile = $true
            $result.TargetPath = $shortcut.TargetPath
            $result.TargetArguments = $shortcut.Arguments
            $result.TargetWorkingDirectory = $shortcut.WorkingDirectory
            
            # Clean up COM objects
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shortcut) | Out-Null
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null
        }
    } catch {
        # LNK analysis failed
    }
    
    return $result
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
                        $fileInfo = Get-FileInfo -FilePath $_.Value
                        
                        # Additional RMM detection based on publisher
                        if ($fileInfo.Publisher -and -not $suspicious.IsSuspicious) {
                            $rmmPublishers = @(
                                "teamviewer", "anydesk", "logmein", "splashtop", "connectwise", "kaseya", "n-able", "continuum",
                                "solarwinds", "pulseway", "aem", "ninja", "atera", "superops", "syncro", "barracuda", "datto",
                                "beyondtrust", "ultravnc", "tightvnc", "realvnc", "radmin", "ammyy", "supremo", "rustdesk",
                                "parsec", "remotix", "nomachine", "noip", "dynu", "duckdns", "freedns", "cloudflare", "screenconnect"
                            )
                            
                            foreach ($publisher in $rmmPublishers) {
                                if ($fileInfo.Publisher -match $publisher) {
                                    $suspicious.IsSuspicious = $true
                                    if ($suspicious.Reason) { $suspicious.Reason += "; " }
                                    $suspicious.Reason += "RMM/Remote Desktop publisher detected: $($fileInfo.Publisher)"
                                    break
                                }
                            }
                        }
                        
                        # Analyze .lnk files for additional information
                        $lnkInfo = Get-LnkTarget -LnkPath $_.Value
                        $targetFileInfo = @{
                            Publisher = ""
                            ImagePath = ""
                            MD5Hash = ""
                            SHA1Hash = ""
                            SHA256Hash = ""
                            Timestamp = ""
                            VerifiedSigner = $false
                        }
                        
                        if ($lnkInfo.IsLnkFile -and $lnkInfo.TargetPath) {
                            $targetFileInfo = Get-FileInfo -FilePath $lnkInfo.TargetPath
                            
                            # Check if the target is suspicious
                            if ($lnkInfo.TargetPath -match "temp|tmp|downloads|desktop|documents|public|appdata\\local\\temp|appdata\\roaming") {
                                $suspicious.IsSuspicious = $true
                                if ($suspicious.Reason) { $suspicious.Reason += "; " }
                                $suspicious.Reason += "LNK target in suspicious location: $($lnkInfo.TargetPath)"
                            }
                            
                            # Check target for RMM software
                            if ($targetFileInfo.Publisher -and -not $suspicious.IsSuspicious) {
                                $rmmPublishers = @(
                                    "teamviewer", "anydesk", "logmein", "splashtop", "connectwise", "kaseya", "n-able", "continuum",
                                    "solarwinds", "pulseway", "aem", "ninja", "atera", "superops", "syncro", "barracuda", "datto",
                                    "beyondtrust", "ultravnc", "tightvnc", "realvnc", "radmin", "ammyy", "supremo", "rustdesk",
                                    "parsec", "remotix", "nomachine", "noip", "dynu", "duckdns", "freedns", "cloudflare", "screenconnect"
                                )
                                
                                foreach ($publisher in $rmmPublishers) {
                                    if ($targetFileInfo.Publisher -match $publisher) {
                                        $suspicious.IsSuspicious = $true
                                        if ($suspicious.Reason) { $suspicious.Reason += "; " }
                                        $suspicious.Reason += "LNK target RMM/Remote Desktop publisher detected: $($targetFileInfo.Publisher)"
                                        break
                                    }
                                }
                            }
                        }
                        
                        $status = if ($suspicious.IsSuspicious) { "RED" } elseif ($suspicious.IsBaseline) { "WHITE" } else { "YELLOW" }
                        $autoruns += [PSCustomObject]@{
                            Status = $status
                            User = $Username
                            Type = "Registry"
                            Location = $regPath
                            Name = $_.Name
                            Command = $_.Value
                            Publisher = if ($lnkInfo.IsLnkFile) { $targetFileInfo.Publisher } else { $fileInfo.Publisher }
                            ImagePath = if ($lnkInfo.IsLnkFile) { $lnkInfo.TargetPath } else { $fileInfo.ImagePath }
                            MD5Hash = if ($lnkInfo.IsLnkFile) { $targetFileInfo.MD5Hash } else { $fileInfo.MD5Hash }
                            SHA1Hash = if ($lnkInfo.IsLnkFile) { $targetFileInfo.SHA1Hash } else { $fileInfo.SHA1Hash }
                            SHA256Hash = if ($lnkInfo.IsLnkFile) { $targetFileInfo.SHA256Hash } else { $fileInfo.SHA256Hash }
                            Timestamp = if ($lnkInfo.IsLnkFile) { $targetFileInfo.Timestamp } else { $fileInfo.Timestamp }
                            VerifiedSigner = if ($lnkInfo.IsLnkFile) { $targetFileInfo.VerifiedSigner } else { $fileInfo.VerifiedSigner }
                            LnkTarget = if ($lnkInfo.IsLnkFile) { $lnkInfo.TargetPath } else { "" }
                            LnkArguments = if ($lnkInfo.IsLnkFile) { $lnkInfo.TargetArguments } else { "" }
                            LnkWorkingDir = if ($lnkInfo.IsLnkFile) { $lnkInfo.TargetWorkingDirectory } else { "" }
                            IsSuspicious = $suspicious.IsSuspicious
                            IsBaseline = $suspicious.IsBaseline
                            Reason = $suspicious.Reason
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
                    $fileInfo = Get-FileInfo -FilePath $_.FullName
                    
                    # Additional RMM detection based on publisher
                    if ($fileInfo.Publisher -and -not $suspicious.IsSuspicious) {
                        $rmmPublishers = @(
                            "teamviewer", "anydesk", "logmein", "splashtop", "connectwise", "kaseya", "n-able", "continuum",
                            "solarwinds", "pulseway", "aem", "ninja", "atera", "superops", "syncro", "barracuda", "datto",
                            "beyondtrust", "ultravnc", "tightvnc", "realvnc", "radmin", "ammyy", "supremo", "rustdesk",
                            "parsec", "remotix", "nomachine", "noip", "dynu", "duckdns", "freedns", "cloudflare"
                        )
                        
                        foreach ($publisher in $rmmPublishers) {
                            if ($fileInfo.Publisher -match $publisher) {
                                $suspicious.IsSuspicious = $true
                                if ($suspicious.Reason) { $suspicious.Reason += "; " }
                                $suspicious.Reason += "RMM/Remote Desktop publisher detected: $($fileInfo.Publisher)"
                                break
                            }
                        }
                    }
                    
                    $status = if ($suspicious.IsSuspicious) { "RED" } elseif ($suspicious.IsBaseline) { "WHITE" } else { "YELLOW" }
                    $autoruns += [PSCustomObject]@{
                        Status = $status
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
                    $fileInfo = Get-FileInfo -FilePath $action.Execute
                    
                    # Additional RMM detection based on publisher
                    if ($fileInfo.Publisher -and -not $suspicious.IsSuspicious) {
                        $rmmPublishers = @(
                            "teamviewer", "anydesk", "logmein", "splashtop", "connectwise", "kaseya", "n-able", "continuum",
                            "solarwinds", "pulseway", "aem", "ninja", "atera", "superops", "syncro", "barracuda", "datto",
                            "beyondtrust", "ultravnc", "tightvnc", "realvnc", "radmin", "ammyy", "supremo", "rustdesk",
                            "parsec", "remotix", "nomachine", "noip", "dynu", "duckdns", "freedns", "cloudflare"
                        )
                        
                        foreach ($publisher in $rmmPublishers) {
                            if ($fileInfo.Publisher -match $publisher) {
                                $suspicious.IsSuspicious = $true
                                if ($suspicious.Reason) { $suspicious.Reason += "; " }
                                $suspicious.Reason += "RMM/Remote Desktop publisher detected: $($fileInfo.Publisher)"
                                break
                            }
                        }
                    }
                    
                    $status = if ($suspicious.IsSuspicious) { "RED" } elseif ($suspicious.IsBaseline) { "WHITE" } else { "YELLOW" }
                    $tasks += [PSCustomObject]@{
                        Status = $status
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
                $fileInfo = Get-FileInfo -FilePath $service.PathName
                
                # Additional RMM detection based on publisher
                if ($fileInfo.Publisher -and -not $suspicious.IsSuspicious) {
                    $rmmPublishers = @(
                        "teamviewer", "anydesk", "logmein", "splashtop", "connectwise", "kaseya", "n-able", "continuum",
                        "solarwinds", "pulseway", "aem", "ninja", "atera", "superops", "syncro", "barracuda", "datto",
                        "beyondtrust", "ultravnc", "tightvnc", "realvnc", "radmin", "ammyy", "supremo", "rustdesk",
                        "parsec", "remotix", "nomachine", "noip", "dynu", "duckdns", "freedns", "cloudflare"
                    )
                    
                    foreach ($publisher in $rmmPublishers) {
                        if ($fileInfo.Publisher -match $publisher) {
                            $suspicious.IsSuspicious = $true
                            if ($suspicious.Reason) { $suspicious.Reason += "; " }
                            $suspicious.Reason += "RMM/Remote Desktop publisher detected: $($fileInfo.Publisher)"
                            break
                        }
                    }
                }
                
                $status = if ($suspicious.IsSuspicious) { "RED" } elseif ($suspicious.IsBaseline) { "WHITE" } else { "YELLOW" }
                $services += [PSCustomObject]@{
                    Status = $status
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
                        $fileInfo = Get-FileInfo -FilePath $logonScript.UserInitMprLogonScript
                        
                        # Additional RMM detection based on publisher
                        if ($fileInfo.Publisher -and -not $suspicious.IsSuspicious) {
                            $rmmPublishers = @(
                                "teamviewer", "anydesk", "logmein", "splashtop", "connectwise", "kaseya", "n-able", "continuum",
                                "solarwinds", "pulseway", "aem", "ninja", "atera", "superops", "syncro", "barracuda", "datto",
                                "beyondtrust", "ultravnc", "tightvnc", "realvnc", "radmin", "ammyy", "supremo", "rustdesk",
                                "parsec", "remotix", "nomachine", "noip", "dynu", "duckdns", "freedns", "cloudflare", "screenconnect"
                            )
                            
                            foreach ($publisher in $rmmPublishers) {
                                if ($fileInfo.Publisher -match $publisher) {
                                    $suspicious.IsSuspicious = $true
                                    if ($suspicious.Reason) { $suspicious.Reason += "; " }
                                    $suspicious.Reason += "RMM/Remote Desktop publisher detected: $($fileInfo.Publisher)"
                                    break
                                }
                            }
                        }
                        
                        $status = if ($suspicious.IsSuspicious) { "RED" } elseif ($suspicious.IsBaseline) { "WHITE" } else { "YELLOW" }
                        $scripts += [PSCustomObject]@{
                            Status = $status
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
    param(
        $OutputPath,
        [switch]$EnableVirusTotal,
        [string]$VTApiKey = "",
        [string]$VTCachePath = ".\vt_cache.json"
    )
    
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

    # VirusTotal enrichment (if enabled)
    if ($EnableVirusTotal -and -not [string]::IsNullOrEmpty($VTApiKey)) {
        Write-Status "VirusTotal checking enabled - enriching results..." "Cyan"

        # Load VT cache
        $vtCache = Get-VTCache -CachePath $VTCachePath
        Write-Status "Loaded VT cache with $($vtCache.Count) entries" "Cyan"

        # Filter to RED and YELLOW items only
        $itemsToCheck = $AllResults | Where-Object { $_.Status -in @('RED', 'YELLOW') -and $_.SHA256Hash -and $_.SHA256Hash.Length -eq 64 }

        # Get unique hashes to avoid duplicate API calls
        $uniqueHashes = $itemsToCheck | Select-Object -ExpandProperty SHA256Hash -Unique
        Write-Status "Found $($itemsToCheck.Count) RED/YELLOW items with $($uniqueHashes.Count) unique hashes" "Cyan"

        # Check how many need querying (not in cache)
        $uncachedHashes = $uniqueHashes | Where-Object { -not $vtCache.ContainsKey($_) }
        $cachedCount = $uniqueHashes.Count - $uncachedHashes.Count

        Write-Status "Cache hits: $cachedCount, New queries needed: $($uncachedHashes.Count)" "Cyan"

        # Rate limiting: 4 requests/minute = 15 seconds between requests
        $rateLimitDelay = 15

        if ($uncachedHashes.Count -gt 0) {
            $estimatedTime = [math]::Ceiling(($uncachedHashes.Count * $rateLimitDelay) / 60)
            Write-Status "Estimated time for VT queries: ~$estimatedTime minutes" "Yellow"
            Write-Status "Note: Free API tier allows 4 requests/min, 500/day" "Yellow"
        }

        # Query VirusTotal for each unique hash
        $processedCount = 0
        foreach ($hash in $uniqueHashes) {
            if (-not $vtCache.ContainsKey($hash)) {
                $processedCount++
                Write-Status "[$processedCount/$($uncachedHashes.Count)] Querying VT for: $($hash.Substring(0,16))..." "Cyan"

                $vtResult = Get-VirusTotalReport -SHA256Hash $hash -ApiKey $VTApiKey -Cache $vtCache

                if ($vtResult.Error -eq "API rate limit exceeded") {
                    Write-Status "Rate limit hit! Saving cache and stopping VT queries..." "Red"
                    break
                }

                # Rate limiting: Wait 15 seconds between requests (4/min)
                if ($processedCount -lt $uncachedHashes.Count) {
                    Write-Verbose "Waiting $rateLimitDelay seconds for rate limit..."
                    Start-Sleep -Seconds $rateLimitDelay
                }
            }
        }

        # Save cache after queries
        Save-VTCache -Cache $vtCache -CachePath $VTCachePath
        Write-Status "VT cache saved with $($vtCache.Count) entries" "Green"

        # Enrich results with VT data
        Write-Status "Enriching results with VT data..." "Cyan"
        foreach ($result in $AllResults) {
            if ($result.SHA256Hash -and $vtCache.ContainsKey($result.SHA256Hash)) {
                $vtData = $vtCache[$result.SHA256Hash]
                $result | Add-Member -NotePropertyName "VT_Detections" -NotePropertyValue $vtData.Detections -Force
                $result | Add-Member -NotePropertyName "VT_Permalink" -NotePropertyValue $vtData.Permalink -Force
                $result | Add-Member -NotePropertyName "VT_Reputation" -NotePropertyValue $vtData.Reputation -Force
            } else {
                $result | Add-Member -NotePropertyName "VT_Detections" -NotePropertyValue "N/A" -Force
                $result | Add-Member -NotePropertyName "VT_Permalink" -NotePropertyValue "" -Force
                $result | Add-Member -NotePropertyName "VT_Reputation" -NotePropertyValue "Not Checked" -Force
            }
        }

        Write-Status "VT enrichment complete!" "Green"
    } else {
        # Add empty VT columns for consistency
        foreach ($result in $AllResults) {
            $result | Add-Member -NotePropertyName "VT_Detections" -NotePropertyValue "Disabled" -Force
            $result | Add-Member -NotePropertyName "VT_Permalink" -NotePropertyValue "" -Force
            $result | Add-Member -NotePropertyName "VT_Reputation" -NotePropertyValue "Disabled" -Force
        }
    }

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
                $worksheet.Name = "Autorun Data"

                # Add color coding - OPTIMIZED: Use Range operations instead of individual cells
                $row = 2  # Start from row 2 (skip header)
                $lastCol = $worksheet.UsedRange.Columns.Count
                foreach ($result in $AllResults) {
                    if ($result.Status -eq "RED") {
                        # Color the entire row red using Range (much faster than cell-by-cell)
                        $worksheet.Range($worksheet.Cells.Item($row, 1), $worksheet.Cells.Item($row, $lastCol)).Interior.Color = 255  # Light Red
                    } elseif ($result.Status -eq "YELLOW") {
                        # Color the entire row yellow using Range
                        $worksheet.Range($worksheet.Cells.Item($row, 1), $worksheet.Cells.Item($row, $lastCol)).Interior.Color = 65535  # Light Yellow
                    } elseif ($result.Status -eq "WHITE") {
                        # Color the entire row white using Range
                        $worksheet.Range($worksheet.Cells.Item($row, 1), $worksheet.Cells.Item($row, $lastCol)).Interior.Color = 16777215  # White
                    }
                    $row++
                }
                
                # Create Analysis Summary with Interactive Tables
                Write-Status "Creating analysis summary with interactive tables..." "Cyan"
                try {
                    # Add a new worksheet for analysis
                    $pivotWorksheet = $workbook.Worksheets.Add()
                    $pivotWorksheet.Name = "Analysis"
                    
                    # Add title
                    $pivotWorksheet.Cells.Item(1, 1) = "Windows Autorun Analysis Summary"
                    $pivotWorksheet.Cells.Item(1, 1).Font.Bold = $true
                    $pivotWorksheet.Cells.Item(1, 1).Font.Size = 14
                    
                    # Create summary statistics
                    $row = 3
                    $pivotWorksheet.Cells.Item($row, 1) = "Total Items:"
                    $pivotWorksheet.Cells.Item($row, 2) = $AllResults.Count
                    $pivotWorksheet.Cells.Item($row, 1).Font.Bold = $true
                    $row++
                    
                    $pivotWorksheet.Cells.Item($row, 1) = "Suspicious (RED):"
                    $pivotWorksheet.Cells.Item($row, 2) = ($AllResults | Where-Object { $_.Status -eq 'RED' }).Count
                    $pivotWorksheet.Cells.Item($row, 1).Font.Bold = $true
                    $row++
                    
                    $pivotWorksheet.Cells.Item($row, 1) = "After-market (YELLOW):"
                    $pivotWorksheet.Cells.Item($row, 2) = ($AllResults | Where-Object { $_.Status -eq 'YELLOW' }).Count
                    $pivotWorksheet.Cells.Item($row, 1).Font.Bold = $true
                    $row++
                    
                    $pivotWorksheet.Cells.Item($row, 1) = "Baseline (WHITE):"
                    $pivotWorksheet.Cells.Item($row, 2) = ($AllResults | Where-Object { $_.Status -eq 'WHITE' }).Count
                    $pivotWorksheet.Cells.Item($row, 1).Font.Bold = $true
                    $row += 3
                    
                    # Create Status breakdown table
                    $pivotWorksheet.Cells.Item($row, 1) = "Breakdown by Status:"
                    $pivotWorksheet.Cells.Item($row, 1).Font.Bold = $true
                    $pivotWorksheet.Cells.Item($row, 1).Font.Size = 12
                    $row++
                    
                    $pivotWorksheet.Cells.Item($row, 1) = "Status"
                    $pivotWorksheet.Cells.Item($row, 2) = "Count"
                    $pivotWorksheet.Cells.Item($row, 3) = "Percentage"
                    $pivotWorksheet.Range("A$row:C$row").Font.Bold = $true
                    $pivotWorksheet.Range("A$row:C$row").Interior.Color = 15773696  # Light blue
                    $row++
                    
                    $statusGroups = $AllResults | Group-Object Status | Sort-Object Count -Descending
                    foreach ($group in $statusGroups) {
                        $percentage = [math]::Round(($group.Count / $AllResults.Count) * 100, 1)
                        $pivotWorksheet.Cells.Item($row, 1) = $group.Name
                        $pivotWorksheet.Cells.Item($row, 2) = $group.Count
                        $pivotWorksheet.Cells.Item($row, 3) = "$percentage%"
                        $row++
                    }
                    $row += 2
                    
                    # Create Type breakdown table
                    $pivotWorksheet.Cells.Item($row, 1) = "Breakdown by Type:"
                    $pivotWorksheet.Cells.Item($row, 1).Font.Bold = $true
                    $pivotWorksheet.Cells.Item($row, 1).Font.Size = 12
                    $row++
                    
                    $pivotWorksheet.Cells.Item($row, 1) = "Type"
                    $pivotWorksheet.Cells.Item($row, 2) = "Count"
                    $pivotWorksheet.Cells.Item($row, 3) = "Percentage"
                    $pivotWorksheet.Range("A$row:C$row").Font.Bold = $true
                    $pivotWorksheet.Range("A$row:C$row").Interior.Color = 15773696  # Light blue
                    $row++
                    
                    $typeGroups = $AllResults | Group-Object Type | Sort-Object Count -Descending
                    foreach ($group in $typeGroups) {
                        $percentage = [math]::Round(($group.Count / $AllResults.Count) * 100, 1)
                        $pivotWorksheet.Cells.Item($row, 1) = $group.Name
                        $pivotWorksheet.Cells.Item($row, 2) = $group.Count
                        $pivotWorksheet.Cells.Item($row, 3) = "$percentage%"
                        $row++
                    }
                    $row += 2
                    
                    # Create User breakdown table
                    $pivotWorksheet.Cells.Item($row, 1) = "Breakdown by User:"
                    $pivotWorksheet.Cells.Item($row, 1).Font.Bold = $true
                    $pivotWorksheet.Cells.Item($row, 1).Font.Size = 12
                    $row++
                    
                    $pivotWorksheet.Cells.Item($row, 1) = "User"
                    $pivotWorksheet.Cells.Item($row, 2) = "Count"
                    $pivotWorksheet.Cells.Item($row, 3) = "Percentage"
                    $pivotWorksheet.Range("A$row:C$row").Font.Bold = $true
                    $pivotWorksheet.Range("A$row:C$row").Interior.Color = 15773696  # Light blue
                    $row++
                    
                    $userGroups = $AllResults | Group-Object User | Sort-Object Count -Descending
                    foreach ($group in $userGroups) {
                        $percentage = [math]::Round(($group.Count / $AllResults.Count) * 100, 1)
                        $pivotWorksheet.Cells.Item($row, 1) = $group.Name
                        $pivotWorksheet.Cells.Item($row, 2) = $group.Count
                        $pivotWorksheet.Cells.Item($row, 3) = "$percentage%"
                        $row++
                    }
                    $row += 2
                    
                    # Create Publisher breakdown table
                    $pivotWorksheet.Cells.Item($row, 1) = "Top Publishers:"
                    $pivotWorksheet.Cells.Item($row, 1).Font.Bold = $true
                    $pivotWorksheet.Cells.Item($row, 1).Font.Size = 12
                    $row++
                    
                    $pivotWorksheet.Cells.Item($row, 1) = "Publisher"
                    $pivotWorksheet.Cells.Item($row, 2) = "Count"
                    $pivotWorksheet.Cells.Item($row, 3) = "Percentage"
                    $pivotWorksheet.Range("A$row:C$row").Font.Bold = $true
                    $pivotWorksheet.Range("A$row:C$row").Interior.Color = 15773696  # Light blue
                    $row++
                    
                    $publisherGroups = $AllResults | Where-Object { $_.Publisher -and $_.Publisher -ne "" } | Group-Object Publisher | Sort-Object Count -Descending | Select-Object -First 15
                    foreach ($group in $publisherGroups) {
                        $percentage = [math]::Round(($group.Count / $AllResults.Count) * 100, 1)
                        $pivotWorksheet.Cells.Item($row, 1) = $group.Name
                        $pivotWorksheet.Cells.Item($row, 2) = $group.Count
                        $pivotWorksheet.Cells.Item($row, 3) = "$percentage%"
                        $row++
                    }
                    
                    # Auto-fit columns
                    $pivotWorksheet.UsedRange.Columns.AutoFit()
                    
                    Write-Status "Interactive analysis summary created successfully" "Green"
                } catch {
                    Write-Status "Analysis summary creation failed: $($_.Exception.Message)" "Yellow"
                    
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
        $csvPath = Start-AutorunAnalysis -OutputPath $OutputPath -EnableVirusTotal:$EnableVirusTotal -VTApiKey $VTApiKey -VTCachePath $VTCachePath
        $success = $true
        # Exit immediately after portable mode execution
        Write-Status "Universal script completed!" "Cyan"
        exit 0
    }
    "auto" {
        Write-Status "Auto mode: Detecting best method..." "Yellow"

        # BUG FIX: Improved recursion detection - check if we're running from a downloaded file
        # Prevents infinite download loops by detecting auto-downloaded scripts
        $currentScriptPath = $MyInvocation.PSCommandPath
        if ($currentScriptPath -and
            ($currentScriptPath -match "WindowsAutorunAnalyzer_(Auto|Downloaded|FromShare)\.ps1$" -or
             $currentScriptPath -match "autorun\.ps1$")) {
            Write-Status "Already running from downloaded script, using portable mode..." "Green"
            $csvPath = Start-AutorunAnalysis -OutputPath $OutputPath -EnableVirusTotal:$EnableVirusTotal -VTApiKey $VTApiKey -VTCachePath $VTCachePath
            $success = $true
            # Exit immediately after portable mode execution
            Write-Status "Universal script completed!" "Cyan"
            exit 0
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
                        $csvPath = Start-AutorunAnalysis -OutputPath $OutputPath -EnableVirusTotal:$EnableVirusTotal -VTApiKey $VTApiKey -VTCachePath $VTCachePath
                        Write-Status "Universal script completed!" "Cyan"
                        exit 0
                    }
                }
            } else {
                Write-Status "No internet, trying local..." "Yellow"
                if (Test-Path $LocalPath) {
                    $scriptPath = $LocalPath
                    $success = $true
                } else {
                    Write-Status "Local not found, using portable mode..." "Yellow"
                    $csvPath = Start-AutorunAnalysis -OutputPath $OutputPath -EnableVirusTotal:$EnableVirusTotal -VTApiKey $VTApiKey -VTCachePath $VTCachePath
                    Write-Status "Universal script completed!" "Cyan"
                    exit 0
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
    # SECURITY FIX: Validate script integrity before execution
    Write-Status "Validating script integrity..." "Cyan"

    if (-not (Test-ScriptIntegrity -ScriptPath $scriptPath)) {
        Write-Status "Script validation failed! Will not execute untrusted script." "Red"
        Write-Status "Falling back to portable mode..." "Yellow"
        Start-AutorunAnalysis -OutputPath $OutputPath -EnableVirusTotal:$EnableVirusTotal -VTApiKey $VTApiKey -VTCachePath $VTCachePath
        Write-Status "Universal script completed!" "Cyan"
        exit 0
    }

    Write-Status "Script validation passed. Executing Windows Autorun Analyzer..." "Green"
    try {
        # BUG FIX: Pass VT parameters to child script
        if ($EnableVirusTotal -and -not [string]::IsNullOrEmpty($VTApiKey)) {
            & $scriptPath -OutputPath $OutputPath -EnableVirusTotal -VTApiKey $VTApiKey -VTCachePath $VTCachePath
        } else {
            & $scriptPath -OutputPath $OutputPath
        }
        # BUG FIX: Exit after successful execution to prevent fall-through
        Write-Status "Analysis completed successfully!" "Green"
        Write-Status "Universal script completed!" "Cyan"
        exit 0
    } catch {
        Write-Status "Error executing script: $($_.Exception.Message)" "Red"
        Write-Status "Falling back to portable mode..." "Yellow"
        Start-AutorunAnalysis -OutputPath $OutputPath -EnableVirusTotal:$EnableVirusTotal -VTApiKey $VTApiKey -VTCachePath $VTCachePath
        Write-Status "Universal script completed!" "Cyan"
        exit 0
    }
}

# Only reach here if no script was executed (portable mode, local mode without script, or failures)
if ($Mode -eq "local") {
    Write-Status "Using built-in analysis engine..." "Green"
    Start-AutorunAnalysis -OutputPath $OutputPath -EnableVirusTotal:$EnableVirusTotal -VTApiKey $VTApiKey -VTCachePath $VTCachePath
} elseif ($Mode -eq "portable") {
    # Already executed in switch block above, just exit
    Write-Status "Universal script completed!" "Cyan"
    exit 0
} elseif (-not $success) {
    Write-Status "Failed to obtain script, using portable mode..." "Yellow"
    Start-AutorunAnalysis -OutputPath $OutputPath -EnableVirusTotal:$EnableVirusTotal -VTApiKey $VTApiKey -VTCachePath $VTCachePath
}

Write-Status "Universal script completed!" "Cyan"

# Windows Autorun Analyzer

A comprehensive PowerShell script for analyzing Windows autoruns, scheduled tasks, services, and registry entries across all user profiles. The script categorizes items as baseline Windows components, after-market software, or suspicious items.

## 🚀 Features

- **Universal Deployment**: Single script handles all scenarios (GitHub, Local, LAN Share, Portable)
- **Comprehensive Analysis**: Scans all user profiles, registry hives, scheduled tasks, services, and startup folders
- **Smart Categorization**: 
  - 🔴 **RED**: Suspicious items (PowerShell/CMD in temp folders)
  - 🟡 **YELLOW**: After-market/third-party software
  - ⚪ **WHITE**: Baseline Windows components
- **Multiple Output Formats**: CSV and Excel support
- **No Dependencies**: Portable version works without external modules
- **Intelligent Fallback**: Never fails - always produces results

## 📋 Quick Start

### Option 1: Interactive Menu
```cmd
run_autorun_analyzer_universal.bat
```

### Option 2: Simple One-Click
```cmd
run_autorun_analyzer_simple.bat
```

### Option 3: Direct PowerShell
```powershell
.\WindowsAutorunAnalyzer_Universal.ps1
```

## 🔧 Usage

### Basic Usage
```powershell
# Auto-detect best method (recommended)
.\WindowsAutorunAnalyzer_Universal.ps1

# Force specific mode
.\WindowsAutorunAnalyzer_Universal.ps1 -Mode portable
```

### Advanced Usage
```powershell
# GitHub mode with custom URL
.\WindowsAutorunAnalyzer_Universal.ps1 -Mode github -GitHubUrl "https://raw.githubusercontent.com/yourusername/repo/main/script.ps1"

# LAN share mode
.\WindowsAutorunAnalyzer_Universal.ps1 -Mode share -SharePath "\\server\share\script.ps1"

# Custom output path
.\WindowsAutorunAnalyzer_Universal.ps1 -OutputPath "C:\reports\analysis_$(Get-Date -Format 'yyyyMMdd').csv"
```

## 📊 Deployment Scenarios

### 🌐 With Internet (GitHub)
- Downloads latest version from GitHub
- Automatic fallback to local if download fails
- Perfect for always-connected environments

### 💻 No Internet (Local)
- Uses local script files
- No external dependencies
- Works completely offline

### 🏢 LAN Share (Network)
- Copies script from network share
- Handles network connectivity issues
- Perfect for enterprise environments

### ⚡ Portable Mode
- Embedded analysis engine
- No external files required
- Always works regardless of environment

## 📁 File Structure

```
├── WindowsAutorunAnalyzer_Universal.ps1    # Main universal script
├── run_autorun_analyzer_universal.bat      # Interactive menu
├── run_autorun_analyzer_simple.bat         # One-click execution
├── README.md                               # This file
└── LICENSE                                 # MIT License
```

## 🔍 What It Analyzes

### Registry Autoruns
- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx`
- `HKU:\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` (per user)
- And many more...

### System Components
- **Scheduled Tasks**: All enabled tasks
- **Services**: Auto-start and manual services
- **Startup Folders**: System and user startup folders
- **Logon Scripts**: User logon scripts

### User Profiles
- All local user profiles
- System accounts (SYSTEM, LOCAL SERVICE, NETWORK SERVICE)
- Per-user registry hives

## 🎯 Output Format

The script generates a CSV file with the following columns:
- **User**: User account name
- **Type**: Registry, Scheduled Task, Service, Startup Folder, Logon Script
- **Location**: Registry path or file location
- **Name**: Item name
- **Command**: Full command/path
- **IsSuspicious**: Boolean flag for suspicious items
- **IsBaseline**: Boolean flag for baseline Windows items
- **Reason**: Explanation for categorization
- **Status**: RED, YELLOW, or WHITE

## 🔒 Security Features

### Suspicious Detection
- PowerShell/CMD scripts in temp folders
- Executables in unusual locations
- Suspicious file extensions in temp areas
- Non-standard installation paths

### Baseline Identification
- Windows system files (`C:\Windows\*`)
- Program Files installations
- Standard startup locations
- Microsoft-signed components

## 🚀 Enterprise Deployment

### Group Policy
```powershell
# Deploy via GPO with share mode
.\WindowsAutorunAnalyzer_Universal.ps1 -Mode share -SharePath "\\domain\scripts\autorun.ps1"
```

### Scheduled Tasks
```powershell
# Daily analysis
.\WindowsAutorunAnalyzer_Universal.ps1 -OutputPath "C:\monitoring\daily_$(Get-Date -Format 'yyyyMMdd').csv"
```

### Incident Response
```powershell
# Quick analysis
.\WindowsAutorunAnalyzer_Universal.ps1 -Mode portable -OutputPath "C:\incident\analysis.csv"
```

## 🔧 Requirements

- **PowerShell 5.1+** (Windows 10/11)
- **Administrator privileges** (for full registry access)
- **No external dependencies** (portable mode)

## 📝 Examples

### Example Output
```
Total items analyzed: 588
Suspicious items (RED): 0
After-market items (YELLOW): 265
Baseline Windows items (WHITE): 323
```

### Sample Results
```csv
User,Type,Location,Name,Command,IsSuspicious,IsBaseline,Reason,Status
Chris,Registry,HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run,SecurityHealth,C:\WINDOWS\system32\SecurityHealthSystray.exe,False,True,,WHITE
Chris,Registry,HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run,UrBackupClient,C:\Program Files\UrBackup\UrBackupClient.exe,False,True,,WHITE
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For issues or questions:
1. Check the troubleshooting section
2. Verify all requirements are met
3. Test with portable mode first
4. Check PowerShell execution logs

## 🔄 Version History

- **v1.0**: Initial release with universal script
- Multi-scenario deployment support
- Comprehensive autorun analysis
- Smart categorization system

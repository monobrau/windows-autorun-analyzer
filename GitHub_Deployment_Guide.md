# GitHub Deployment Guide

## 🚀 How to Push to GitHub

### Step 1: Create GitHub Repository

1. Go to [GitHub.com](https://github.com)
2. Click "New repository"
3. Name it: `windows-autorun-analyzer`
4. Description: "Universal Windows Autorun Analyzer - PowerShell script for analyzing autoruns, scheduled tasks, services, and registry entries"
5. Make it **Public** (so the raw URLs work)
6. Don't initialize with README (we have one)
7. Click "Create repository"

### Step 2: Initialize Local Git Repository

```bash
# Navigate to your project directory
cd C:\dev

# Initialize git repository
git init

# Add all files
git add .

# Make initial commit
git commit -m "Initial commit: Universal Windows Autorun Analyzer"

# Add remote origin (replace YOUR_USERNAME with your GitHub username)
git remote add origin https://github.com/YOUR_USERNAME/windows-autorun-analyzer.git

# Push to GitHub
git push -u origin main
```

### Step 3: Update the Script for GitHub URLs

After pushing, update the GitHub URL in the script:

1. Go to your repository on GitHub
2. Click on `WindowsAutorunAnalyzer_Universal.ps1`
3. Click "Raw" button
4. Copy the raw URL (it will look like: `https://raw.githubusercontent.com/YOUR_USERNAME/windows-autorun-analyzer/main/WindowsAutorunAnalyzer_Universal.ps1`)

5. Update the script with your actual GitHub URL:
```powershell
# In WindowsAutorunAnalyzer_Universal.ps1, change this line:
[string]$GitHubUrl = "https://raw.githubusercontent.com/YOUR_USERNAME/windows-autorun-analyzer/main/WindowsAutorunAnalyzer_Universal.ps1"
```

### Step 4: Test GitHub Deployment

```powershell
# Test downloading from GitHub
.\WindowsAutorunAnalyzer_Universal.ps1 -Mode github

# Test auto-detection
.\WindowsAutorunAnalyzer_Universal.ps1
```

## 📁 Files to Include in Repository

### Core Files
- `WindowsAutorunAnalyzer_Universal.ps1` - Main universal script
- `run_autorun_analyzer_universal.bat` - Interactive menu
- `run_autorun_analyzer_simple.bat` - One-click execution
- `README.md` - Documentation
- `LICENSE` - MIT License
- `.gitignore` - Git ignore rules

### Optional Files
- `WindowsAutorunAnalyzer.ps1` - Original full version
- `WindowsAutorunAnalyzer_Portable.ps1` - Portable version
- `Deploy_*.ps1` - Individual deployment scripts

## 🔧 GitHub Repository Settings

### Repository Settings
1. Go to Settings → General
2. Set default branch to `main`
3. Enable "Issues" and "Discussions"
4. Enable "Wiki" (optional)

### Branch Protection (Optional)
1. Go to Settings → Branches
2. Add rule for `main` branch
3. Require pull request reviews
4. Require status checks

## 📋 Usage After GitHub Deployment

### For Users
```powershell
# Download and run directly from GitHub
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/YOUR_USERNAME/windows-autorun-analyzer/main/WindowsAutorunAnalyzer_Universal.ps1" -OutFile "autorun.ps1"
.\autorun.ps1
```

### For Enterprise Deployment
```powershell
# Deploy via GPO with GitHub URL
.\WindowsAutorunAnalyzer_Universal.ps1 -Mode github -GitHubUrl "https://raw.githubusercontent.com/YOUR_USERNAME/windows-autorun-analyzer/main/WindowsAutorunAnalyzer_Universal.ps1"
```

## 🔄 Updating the Repository

### Regular Updates
```bash
# Make changes to files
# Add changes
git add .

# Commit changes
git commit -m "Update: [description of changes]"

# Push to GitHub
git push origin main
```

### Version Tags
```bash
# Create version tag
git tag -a v1.0 -m "Version 1.0: Initial release"

# Push tags
git push origin v1.0
```

## 🚀 GitHub Actions (Optional)

Create `.github/workflows/ci.yml` for automated testing:

```yaml
name: CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: windows-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Test PowerShell Script
      run: |
        powershell -ExecutionPolicy Bypass -File "WindowsAutorunAnalyzer_Universal.ps1" -Mode portable -OutputPath "test_output.csv"
        
    - name: Verify Output
      run: |
        if (Test-Path "test_output.csv") {
          Write-Host "✅ Test passed - Output file created"
        } else {
          Write-Host "❌ Test failed - No output file"
          exit 1
        }
```

## 📊 Repository Statistics

After deployment, you can track:
- Download counts
- Star counts
- Fork counts
- Issue reports
- Pull requests

## 🎯 Marketing Your Repository

### GitHub Repository Description
```
Universal Windows Autorun Analyzer - PowerShell script for analyzing autoruns, scheduled tasks, services, and registry entries. Supports GitHub, Local, LAN Share, and Portable deployment modes.
```

### Topics/Tags
- `powershell`
- `windows`
- `security`
- `autorun`
- `forensics`
- `incident-response`
- `system-administration`

### Social Media
- Share on LinkedIn
- Post on Reddit (r/PowerShell, r/sysadmin)
- Tweet about it
- Add to your portfolio

## ✅ Checklist Before Going Live

- [ ] Repository created and public
- [ ] All files committed and pushed
- [ ] GitHub URL updated in script
- [ ] README.md is comprehensive
- [ ] LICENSE file included
- [ ] .gitignore configured
- [ ] Tested GitHub download
- [ ] Tested auto-detection mode
- [ ] Repository description set
- [ ] Topics/tags added

## 🚀 You're Ready!

Your Windows Autorun Analyzer is now ready for GitHub deployment. Users can download and run it directly from your repository!

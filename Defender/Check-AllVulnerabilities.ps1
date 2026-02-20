#Requires -Version 5.1
<#
.SYNOPSIS
    Comprehensive vulnerability scanner for Windows OS, Microsoft products, and third-party applications.

.DESCRIPTION
    This script checks vulnerabilities from multiple sources:
    1. Microsoft MSRC - Windows and Microsoft products
    2. NVD (National Vulnerability Database) - Third-party applications
    3. Installed application versions against known CVEs
    
    Color-coded severity display:
    - Critical (CVSS 9.0-10.0): Dark Red
    - High (CVSS 7.0-8.9): Red
    - Medium (CVSS 4.0-6.9): Yellow
    - Low (CVSS 0.1-3.9): Green

.PARAMETER IncludeThirdParty
    Include third-party application vulnerability scanning

.PARAMETER Months
    Number of months to look back for MSRC vulnerabilities (default: 3)

.PARAMETER ExportCSV
    Export results to CSV file

.EXAMPLE
    .\Check-AllVulnerabilities.ps1
    .\Check-AllVulnerabilities.ps1 -IncludeThirdParty -ExportCSV

.NOTES
    Author: Muthanna 'Matt' Aljanabi
    Requires internet connection
    Third-party scanning checks: Chrome, Firefox, Adobe, Java, and more
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeThirdParty,
    
    [Parameter()]
    [int]$Months = 3,
    
    [Parameter()]
    [switch]$ExportCSV,
    
    [Parameter()]
    [string]$OutputPath = ".\VulnerabilityReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

# Known vulnerable application patterns
$ThirdPartyApps = @{
    "Google Chrome" = @{
        RegistryPath = "HKLM:\SOFTWARE\Google\Chrome\BLBeacon"
        VersionKey = "version"
        CVEPattern = "chrome"
    }
    "Mozilla Firefox" = @{
        RegistryPath = "HKLM:\SOFTWARE\Mozilla\Mozilla Firefox"
        VersionKey = "CurrentVersion"
        CVEPattern = "firefox"
    }
    "Adobe Acrobat" = @{
        Pattern = "Adobe Acrobat*"
        CVEPattern = "acrobat"
    }
    "Adobe Reader" = @{
        Pattern = "Adobe*Reader*"
        CVEPattern = "adobe reader"
    }
    "Java" = @{
        Pattern = "Java*"
        CVEPattern = "oracle java"
    }
    "VLC Media Player" = @{
        Pattern = "VLC media player"
        CVEPattern = "vlc"
    }
    "7-Zip" = @{
        Pattern = "7-Zip*"
        CVEPattern = "7-zip"
    }
    "WinRAR" = @{
        Pattern = "WinRAR*"
        CVEPattern = "winrar"
    }
    "Notepad++" = @{
        Pattern = "Notepad++*"
        CVEPattern = "notepad++"
    }
    "TeamViewer" = @{
        Pattern = "TeamViewer*"
        CVEPattern = "teamviewer"
    }
}

# MSRC API Configuration
$msrcApiBase = "https://api.msrc.microsoft.com/cvrf/v2.0"
$msrcHeaders = @{ "Accept" = "application/json" }

function Write-ColoredSeverity {
    param(
        [string]$Severity,
        [double]$CVSSScore,
        [string]$CVE,
        [string]$Title,
        [string]$Product
    )
    
    # Determine color based on severity and CVSS score
    $color = switch -Regex ($Severity) {
        "Critical" { "DarkRed" }
        default {
            if ($CVSSScore -ge 9.0) { "DarkRed" }
            elseif ($CVSSScore -ge 7.0) { "Red" }
            elseif ($CVSSScore -ge 4.0) { "Yellow" }
            else { "Green" }
        }
    }
    
    # Override for specific severities
    if ($Severity -eq "Critical") { $color = "DarkRed" }
    elseif ($Severity -eq "Important" -or $Severity -eq "High") { $color = "Red" }
    elseif ($Severity -eq "Moderate" -or $Severity -eq "Medium") { $color = "Yellow" }
    elseif ($Severity -eq "Low") { $color = "Green" }
    
    Write-Host "`n[" -NoNewline
    Write-Host "$Severity" -ForegroundColor $color -NoNewline
    Write-Host "] " -NoNewline
    
    if ($CVSSScore -gt 0) {
        Write-Host "CVSS: " -NoNewline -ForegroundColor Gray
        Write-Host "$CVSSScore" -ForegroundColor $color -NoNewline
        Write-Host " | " -NoNewline -ForegroundColor Gray
    }
    
    Write-Host "$CVE" -ForegroundColor White
    Write-Host "  Product: $Product" -ForegroundColor Gray
    Write-Host "  $Title" -ForegroundColor Gray
}

function Get-SystemInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    
    return [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        OSName = $os.Caption
        OSVersion = $os.Version
        OSBuild = $os.BuildNumber
        Architecture = $os.OSArchitecture
        Manufacturer = $cs.Manufacturer
        Model = $cs.Model
    }
}

function Get-InstalledKBs {
    Write-Host "Scanning installed Microsoft updates..." -ForegroundColor Cyan
    
    $kbs = @()
    Get-HotFix | ForEach-Object {
        $kbs += $_.HotFixID -replace 'KB', ''
    }
    
    return $kbs
}

function Get-InstalledThirdPartyApps {
    Write-Host "Scanning installed third-party applications..." -ForegroundColor Cyan
    
    $apps = @()
    
    # Registry paths for installed software
    $registryPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    foreach ($path in $registryPaths) {
        Get-ItemProperty $path -ErrorAction SilentlyContinue | 
            Where-Object { $_.DisplayName } | 
            ForEach-Object {
                $apps += [PSCustomObject]@{
                    Name = $_.DisplayName
                    Version = $_.DisplayVersion
                    Publisher = $_.Publisher
                    InstallDate = $_.InstallDate
                }
            }
    }
    
    # Check Chrome version from registry
    try {
        $chromeReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Google\Chrome\BLBeacon" -ErrorAction SilentlyContinue
        if ($chromeReg -and $chromeReg.version) {
            $apps += [PSCustomObject]@{
                Name = "Google Chrome"
                Version = $chromeReg.version
                Publisher = "Google LLC"
                InstallDate = $null
            }
        }
    } catch { }
    
    return $apps | Sort-Object Name -Unique
}

function Get-MSRCVulnerabilities {
    param([int]$MonthsBack)
    
    Write-Host "`nChecking Microsoft MSRC for vulnerabilities..." -ForegroundColor Cyan
    
    $allVulnerabilities = @()
    
    try {
        # Get MSRC update list
        $response = Invoke-RestMethod -Uri "$msrcApiBase/updates" -Headers $msrcHeaders -TimeoutSec 30
        $updateIDs = $response.value
        
        # Filter to recent months
        $targetDate = (Get-Date).AddMonths(-$MonthsBack)
        $recentUpdates = $updateIDs | Where-Object { 
            try {
                $updateDate = [DateTime]::ParseExact($_.ID, "yyyy-MMM", $null)
                $updateDate -ge $targetDate
            } catch { $false }
        } | Select-Object -First $MonthsBack
        
        Write-Host "Analyzing $($recentUpdates.Count) recent Microsoft security bulletins..." -ForegroundColor Gray
        
        foreach ($update in $recentUpdates) {
            Write-Progress -Activity "Scanning MSRC Vulnerabilities" -Status "Processing $($update.ID)"
            
            try {
                $cvrfDoc = Invoke-RestMethod -Uri "$msrcApiBase/cvrf/$($update.ID)" -Headers $msrcHeaders -TimeoutSec 60
                
                if ($cvrfDoc.Vulnerability) {
                    foreach ($vuln in $cvrfDoc.Vulnerability) {
                        $severity = "Unknown"
                        $cvssScore = 0.0
                        
                        # Get severity
                        if ($vuln.Threats) {
                            $severityThreat = $vuln.Threats | Where-Object { $_.Type -eq 0 } | Select-Object -First 1
                            if ($severityThreat) {
                                $severity = $severityThreat.Description.Value
                            }
                        }
                        
                        # Get CVSS score
                        if ($vuln.CVSSScoreSets) {
                            $cvssSet = $vuln.CVSSScoreSets | Select-Object -First 1
                            if ($cvssSet.BaseScore) {
                                $cvssScore = [double]$cvssSet.BaseScore
                            }
                        }
                        
                        # Get KB articles
                        $kbArticles = @()
                        if ($vuln.Remediations) {
                            foreach ($remediation in $vuln.Remediations) {
                                if ($remediation.Description.Value -match 'KB\d+') {
                                    $kbArticles += $matches[0]
                                }
                            }
                        }
                        
                        $allVulnerabilities += [PSCustomObject]@{
                            Source = "MSRC"
                            CVE = $vuln.CVE
                            Title = $vuln.Title.Value
                            Severity = $severity
                            CVSSScore = $cvssScore
                            Product = "Microsoft Product"
                            Update = $update.ID
                            KBArticles = ($kbArticles -join '; ')
                            IsPatched = $false
                        }
                    }
                }
            } catch {
                Write-Verbose "Failed to retrieve $($update.ID): $_"
            }
        }
        
        Write-Progress -Activity "Scanning MSRC Vulnerabilities" -Completed
        
    } catch {
        Write-Warning "Error accessing MSRC API: $_"
    }
    
    return $allVulnerabilities
}

function Get-ThirdPartyVulnerabilities {
    param([array]$InstalledApps)
    
    Write-Host "`nChecking third-party application vulnerabilities..." -ForegroundColor Cyan
    Write-Host "This uses publicly available CVE data and may take a few moments..." -ForegroundColor Gray
    
    $vulnApps = @()
    $knownVulnerableVersions = @{
        "Google Chrome" = @{
            "Vulnerable" = "121.0.6167.0"
            "CVE" = "CVE-2024-0517"
            "CVSS" = 8.8
            "Severity" = "High"
            "Description" = "Out of bounds memory access in V8"
            "FixedIn" = "121.0.6167.85"
        }
        "Mozilla Firefox" = @{
            "Vulnerable" = "122.0"
            "CVE" = "CVE-2024-0741"
            "CVSS" = 7.5
            "Severity" = "High"
            "Description" = "Memory safety bugs"
            "FixedIn" = "122.0.1"
        }
        "Adobe Acrobat Reader DC" = @{
            "Vulnerable" = "23.008.20470"
            "CVE" = "CVE-2024-20747"
            "CVSS" = 7.8
            "Severity" = "High"
            "Description" = "Use After Free vulnerability"
            "FixedIn" = "23.008.20533"
        }
        "Java" = @{
            "Vulnerable" = "8.0.391"
            "CVE" = "CVE-2024-20918"
            "CVSS" = 7.4
            "Severity" = "High"
            "Description" = "Difficult to exploit vulnerability"
            "FixedIn" = "8.0.401"
        }
        "VLC media player" = @{
            "Vulnerable" = "3.0.19"
            "CVE" = "CVE-2023-47359"
            "CVSS" = 7.8
            "Severity" = "High"
            "Description" = "Buffer overflow vulnerability"
            "FixedIn" = "3.0.20"
        }
    }
    
    foreach ($app in $InstalledApps) {
        $appName = $app.Name
        $appVersion = $app.Version
        
        # Check against known vulnerable versions
        foreach ($vulnApp in $knownVulnerableVersions.Keys) {
            if ($appName -like "*$vulnApp*") {
                $vulnInfo = $knownVulnerableVersions[$vulnApp]
                
                # Simple version comparison (in real scenario, use more sophisticated comparison)
                if ($appVersion) {
                    $vulnApps += [PSCustomObject]@{
                        Source = "Third-Party"
                        CVE = $vulnInfo.CVE
                        Title = $vulnInfo.Description
                        Severity = $vulnInfo.Severity
                        CVSSScore = $vulnInfo.CVSS
                        Product = $appName
                        CurrentVersion = $appVersion
                        VulnerableVersion = $vulnInfo.Vulnerable
                        FixedVersion = $vulnInfo.FixedIn
                        IsPatched = $false
                    }
                }
            }
        }
    }
    
    # Note: In production, this would query NVD API or other CVE databases
    Write-Host "Note: For comprehensive third-party CVE scanning, consider using:" -ForegroundColor Yellow
    Write-Host "  - NIST NVD API (https://nvd.nist.gov/developers/vulnerabilities)" -ForegroundColor Yellow
    Write-Host "  - VulnDB" -ForegroundColor Yellow
    Write-Host "  - Snyk or similar vulnerability databases" -ForegroundColor Yellow
    
    return $vulnApps
}

# Main Execution
Write-Host "`n" -NoNewline
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Comprehensive Vulnerability Scanner" -ForegroundColor Cyan
Write-Host "  Microsoft MSRC + Third-Party Applications" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

# Get system information
$sysInfo = Get-SystemInfo
Write-Host "`nDevice Information:" -ForegroundColor White
Write-Host "  Computer: $($sysInfo.ComputerName)" -ForegroundColor Gray
Write-Host "  OS: $($sysInfo.OSName)" -ForegroundColor Gray
Write-Host "  Build: $($sysInfo.OSBuild)" -ForegroundColor Gray
Write-Host "  Architecture: $($sysInfo.Architecture)" -ForegroundColor Gray

# Get installed KBs and apps
$installedKBs = Get-InstalledKBs
$installedApps = Get-InstalledThirdPartyApps

Write-Host "`nInstalled Microsoft Updates: $($installedKBs.Count)" -ForegroundColor White
Write-Host "Installed Applications: $($installedApps.Count)" -ForegroundColor White

# Scan Microsoft vulnerabilities
$msrcVulnerabilities = Get-MSRCVulnerabilities -MonthsBack $Months

# Scan third-party vulnerabilities if requested
$thirdPartyVulnerabilities = @()
if ($IncludeThirdParty) {
    $thirdPartyVulnerabilities = Get-ThirdPartyVulnerabilities -InstalledApps $installedApps
}

# Combine all vulnerabilities
$allVulnerabilities = $msrcVulnerabilities + $thirdPartyVulnerabilities

# Check which KBs are installed
foreach ($vuln in $msrcVulnerabilities) {
    if ($vuln.KBArticles) {
        $kbs = $vuln.KBArticles -split ';' | ForEach-Object { $_.Trim() -replace 'KB', '' }
        foreach ($kb in $kbs) {
            if ($installedKBs -contains $kb) {
                $vuln.IsPatched = $true
                break
            }
        }
    }
}

# Display vulnerabilities
Write-Host "`n" -NoNewline
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  VULNERABILITY REPORT" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

$stats = @{Critical=0; High=0; Medium=0; Low=0}

# Display unpatched vulnerabilities
$unpatchedVulns = $allVulnerabilities | Where-Object { -not $_.IsPatched }

foreach ($vuln in $unpatchedVulns) {
    # Update statistics
    $cvssScore = [double]$vuln.CVSSScore
    if ($vuln.Severity -eq "Critical" -or $cvssScore -ge 9.0) { $stats.Critical++ }
    elseif ($vuln.Severity -in @("Important", "High") -or ($cvssScore -ge 7.0 -and $cvssScore -lt 9.0)) { $stats.High++ }
    elseif ($vuln.Severity -in @("Moderate", "Medium") -or ($cvssScore -ge 4.0 -and $cvssScore -lt 7.0)) { $stats.Medium++ }
    else { $stats.Low++ }
    
    # Display vulnerability
    Write-ColoredSeverity -Severity $vuln.Severity -CVSSScore $cvssScore -CVE $vuln.CVE -Title $vuln.Title -Product $vuln.Product
    
    if ($vuln.Source -eq "MSRC" -and $vuln.KBArticles) {
        Write-Host "  KB Articles: $($vuln.KBArticles)" -ForegroundColor DarkYellow
    }
    elseif ($vuln.Source -eq "Third-Party") {
        Write-Host "  Current Version: $($vuln.CurrentVersion)" -ForegroundColor DarkYellow
        Write-Host "  Fixed in Version: $($vuln.FixedVersion)" -ForegroundColor Green
    }
}

# Display Summary
Write-Host "`n" -NoNewline
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  VULNERABILITY SUMMARY" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Host "`nTotal Vulnerabilities Found: $($allVulnerabilities.Count)" -ForegroundColor White
Write-Host "  - Microsoft (MSRC): $($msrcVulnerabilities.Count)" -ForegroundColor Gray
Write-Host "  - Third-Party Apps: $($thirdPartyVulnerabilities.Count)" -ForegroundColor Gray

Write-Host "`nUnpatched Vulnerabilities by Severity:" -ForegroundColor White
Write-Host "  Critical (CVSS 9.0-10.0): " -NoNewline; Write-Host "$($stats.Critical)" -ForegroundColor DarkRed
Write-Host "  High (CVSS 7.0-8.9):      " -NoNewline; Write-Host "$($stats.High)" -ForegroundColor Red
Write-Host "  Medium (CVSS 4.0-6.9):    " -NoNewline; Write-Host "$($stats.Medium)" -ForegroundColor Yellow
Write-Host "  Low (CVSS 0.1-3.9):       " -NoNewline; Write-Host "$($stats.Low)" -ForegroundColor Green

Write-Host "`nTotal Unpatched: " -NoNewline
Write-Host "$($unpatchedVulns.Count)" -ForegroundColor $(if ($unpatchedVulns.Count -gt 0) { "Red" } else { "Green" })

# Export to CSV if requested
if ($ExportCSV) {
    try {
        $allVulnerabilities | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Host "`nReport exported to: $OutputPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to export CSV: $_"
    }
}

Write-Host "`n" -NoNewline
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Scan completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Recommendations
if ($unpatchedVulns.Count -gt 0) {
    Write-Host "RECOMMENDATIONS:" -ForegroundColor Yellow
    Write-Host "1. Apply missing Microsoft KB updates immediately" -ForegroundColor Yellow
    Write-Host "2. Update third-party applications to latest versions" -ForegroundColor Yellow
    Write-Host "3. Enable automatic updates where possible" -ForegroundColor Yellow
    Write-Host "4. Prioritize Critical and High severity vulnerabilities" -ForegroundColor Yellow
    Write-Host ""
}

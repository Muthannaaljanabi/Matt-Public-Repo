#Requires -Version 5.1
<#
.SYNOPSIS
    Checks for Windows vulnerabilities using MSRC API with color-coded severity display.

.DESCRIPTION
    This script queries the Microsoft Security Response Center (MSRC) API to identify
    vulnerabilities affecting the current system. Results are color-coded by severity:
    - Critical (CVSS 9.0-10.0): Dark Red
    - High (CVSS 7.0-8.9): Red  
    - Medium (CVSS 4.0-6.9): Yellow
    - Low (CVSS 0.1-3.9): Green

.PARAMETER Months
    Number of months to look back for vulnerabilities (default: 3)

.PARAMETER ExportCSV
    Export results to CSV file

.EXAMPLE
    .\Check-MSRCVulnerabilities-API.ps1
    .\Check-MSRCVulnerabilities-API.ps1 -Months 6 -ExportCSV

.NOTES
Author: Muthanna 'Matt' Aljanabi
    Requires internet connection to access MSRC API
#>

[CmdletBinding()]
param(
    [Parameter()]
    [int]$Months = 3,
    
    [Parameter()]
    [switch]$ExportCSV,
    
    [Parameter()]
    [string]$OutputPath = ".\VulnerabilityReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

# MSRC API Configuration
$msrcApiBase = "https://api.msrc.microsoft.com/cvrf/v2.0"
$headers = @{
    "Accept" = "application/json"
}

function Write-ColoredSeverity {
    param(
        [string]$Severity,
        [double]$CVSSScore,
        [string]$CVE,
        [string]$Title
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
    
    # Override color for specific severity levels regardless of score
    if ($Severity -eq "Critical") { $color = "DarkRed" }
    elseif ($Severity -eq "Important") { $color = "Red" }
    elseif ($Severity -eq "Moderate") { $color = "Yellow" }
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
    Write-Host "  $Title" -ForegroundColor Gray
}

function Get-MSRCUpdateIDs {
    Write-Host "Retrieving available MSRC security updates..." -ForegroundColor Cyan
    
    try {
        $response = Invoke-RestMethod -Uri "$msrcApiBase/updates" -Headers $headers -TimeoutSec 30
        return $response.value
    }
    catch {
        Write-Error "Failed to retrieve MSRC update list: $_"
        return $null
    }
}

function Get-MSRCCVRFDocument {
    param([string]$UpdateID)
    
    try {
        $uri = "$msrcApiBase/cvrf/$UpdateID"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -TimeoutSec 60
        return $response
    }
    catch {
        Write-Verbose "Failed to retrieve CVRF document for $UpdateID : $_"
        return $null
    }
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
    Write-Host "Scanning installed updates..." -ForegroundColor Cyan
    
    $kbs = @()
    
    # Get installed hotfixes
    Get-HotFix | ForEach-Object {
        $kbs += $_.HotFixID -replace 'KB', ''
    }
    
    return $kbs
}

# Main Execution
Write-Host "`n" -NoNewline
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Microsoft Security Response Center Vulnerability Scanner" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

# Get system information
$sysInfo = Get-SystemInfo
Write-Host "`nDevice Information:" -ForegroundColor White
Write-Host "  Computer: $($sysInfo.ComputerName)" -ForegroundColor Gray
Write-Host "  OS: $($sysInfo.OSName)" -ForegroundColor Gray
Write-Host "  Build: $($sysInfo.OSBuild)" -ForegroundColor Gray
Write-Host "  Architecture: $($sysInfo.Architecture)" -ForegroundColor Gray

# Get installed KBs
$installedKBs = Get-InstalledKBs
Write-Host "`nInstalled Updates: $($installedKBs.Count)" -ForegroundColor White

# Get MSRC updates for recent months
$updateIDs = Get-MSRCUpdateIDs

if (-not $updateIDs) {
    Write-Error "Unable to retrieve MSRC update list. Please check your internet connection."
    exit 1
}

# Filter to recent months
$targetDate = (Get-Date).AddMonths(-$Months)
$recentUpdates = $updateIDs | Where-Object { 
    try {
        $updateDate = [DateTime]::ParseExact($_.ID, "yyyy-MMM", $null)
        $updateDate -ge $targetDate
    }
    catch {
        $false
    }
} | Select-Object -First $Months

Write-Host "`nAnalyzing $($recentUpdates.Count) recent security bulletins..." -ForegroundColor Cyan
Write-Host "Date Range: $(Get-Date $targetDate -Format 'yyyy-MMM') to $(Get-Date -Format 'yyyy-MMM')" -ForegroundColor Gray

# Process vulnerabilities
$allVulnerabilities = @()
$stats = @{Critical=0; Important=0; Moderate=0; Low=0; Unknown=0}

foreach ($update in $recentUpdates) {
    Write-Host "`nProcessing $($update.ID)..." -ForegroundColor DarkGray
    
    $cvrfDoc = Get-MSRCCVRFDocument -UpdateID $update.ID
    
    if (-not $cvrfDoc) {
        continue
    }
    
    # Extract vulnerabilities
    if ($cvrfDoc.Vulnerability) {
        foreach ($vuln in $cvrfDoc.Vulnerability) {
            $cveID = $vuln.CVE
            $title = $vuln.Title.Value
            
            # Get highest severity rating
            $severity = "Unknown"
            $cvssScore = 0.0
            
            if ($vuln.Threats) {
                $severityThreat = $vuln.Threats | Where-Object { $_.Type -eq 0 } | Select-Object -First 1
                if ($severityThreat) {
                    $severity = $severityThreat.Description.Value
                }
            }
            
            # Get CVSS score if available
            if ($vuln.CVSSScoreSets) {
                $cvssSet = $vuln.CVSSScoreSets | Select-Object -First 1
                if ($cvssSet.BaseScore) {
                    $cvssScore = [double]$cvssSet.BaseScore
                }
            }
            
            # Get affected products
            $affectedProducts = @()
            if ($vuln.ProductStatuses) {
                foreach ($status in $vuln.ProductStatuses) {
                    if ($status.Type -eq 1) { # Known Affected
                        $affectedProducts += $status.ProductID
                    }
                }
            }
            
            # Get remediation (KB articles)
            $kbArticles = @()
            if ($vuln.Remediations) {
                foreach ($remediation in $vuln.Remediations) {
                    if ($remediation.Description.Value -match 'KB\d+') {
                        $kbArticles += $matches[0]
                    }
                }
            }
            
            # Check if any KB is installed
            $isPatched = $false
            foreach ($kb in $kbArticles) {
                $kbNumber = $kb -replace 'KB', ''
                if ($installedKBs -contains $kbNumber) {
                    $isPatched = $true
                    break
                }
            }
            
            # Update statistics
            switch ($severity) {
                "Critical" { $stats.Critical++ }
                "Important" { $stats.Important++ }
                "Moderate" { $stats.Moderate++ }
                "Low" { $stats.Low++ }
                default { $stats.Unknown++ }
            }
            
            # Display vulnerability with color coding
            if (-not $isPatched) {
                Write-ColoredSeverity -Severity $severity -CVSSScore $cvssScore -CVE $cveID -Title $title
                Write-Host "  KB Articles: $($kbArticles -join ', ')" -ForegroundColor DarkYellow
                Write-Host "  Status: NOT PATCHED" -ForegroundColor Red
            }
            
            # Store for export
            $allVulnerabilities += [PSCustomObject]@{
                CVE = $cveID
                Title = $title
                Severity = $severity
                CVSSScore = $cvssScore
                Update = $update.ID
                KBArticles = ($kbArticles -join '; ')
                IsPatched = $isPatched
                AffectedProducts = ($affectedProducts -join '; ')
            }
        }
    }
}

# Display Summary
Write-Host "`n" -NoNewline
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  VULNERABILITY SUMMARY" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Host "`nTotal Vulnerabilities Found: $($allVulnerabilities.Count)" -ForegroundColor White
Write-Host "`nBy Severity:" -ForegroundColor White
Write-Host "  Critical:  " -NoNewline; Write-Host "$($stats.Critical)" -ForegroundColor DarkRed
Write-Host "  Important: " -NoNewline; Write-Host "$($stats.Important)" -ForegroundColor Red
Write-Host "  Moderate:  " -NoNewline; Write-Host "$($stats.Moderate)" -ForegroundColor Yellow
Write-Host "  Low:       " -NoNewline; Write-Host "$($stats.Low)" -ForegroundColor Green

$unpatched = $allVulnerabilities | Where-Object { -not $_.IsPatched }
Write-Host "`nUnpatched Vulnerabilities: " -NoNewline
Write-Host "$($unpatched.Count)" -ForegroundColor $(if ($unpatched.Count -gt 0) { "Red" } else { "Green" })

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

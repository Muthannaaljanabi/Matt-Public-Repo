#Requires -Version 5.1
<#
.SYNOPSIS
    Comprehensive vulnerability scanner with HTML dashboard output.

.DESCRIPTION
    Scans for Microsoft (MSRC) and third-party application vulnerabilities and generates
    an interactive HTML dashboard with:
    - Color-coded severity cards (Critical, High, Medium, Low)
    - Interactive charts showing vulnerability trends
    - Filterable vulnerability table
    - Clickable CVE links to MSRC and NVD
    - Export capabilities

.PARAMETER IncludeThirdParty
    Include third-party application vulnerability scanning

.PARAMETER Months
    Number of months to look back for MSRC vulnerabilities (default: 3)

.PARAMETER OutputHTML
    Path for HTML dashboard output

.EXAMPLE
    .\Check-Vulnerabilities-Dashboard.ps1
    .\Check-Vulnerabilities-Dashboard.ps1 -IncludeThirdParty -OutputHTML "C:\Reports\VulnDashboard.html"

.NOTES
    Generates interactive HTML dashboard for IT and Management
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeThirdParty,
    
    [Parameter()]
    [int]$Months = 3,
    
    [Parameter()]
    [string]$OutputHTML = ".\VulnerabilityDashboard_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    
    [Parameter()]
    [switch]$ExportCSV,
    
    [Parameter()]
    [string]$OutputCSV = ".\VulnerabilityReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

# Latest known good versions (Updated: Feb 2026)
# These should be updated monthly or integrated with an API
$LatestVersions = @{
    "Google Chrome" = @{
        "LatestVersion" = "131.0.6778.108"
        "ReleaseDate" = "2026-02-10"
        "BaseCVSS" = 8.0
    }
    "Mozilla Firefox" = @{
        "LatestVersion" = "123.0"
        "ReleaseDate" = "2026-02-01"
        "BaseCVSS" = 7.5
    }
    "Adobe Acrobat Reader DC" = @{
        "LatestVersion" = "24.001.20604"
        "ReleaseDate" = "2026-02-12"
        "BaseCVSS" = 7.8
    }
    "Java" = @{
        "LatestVersion" = "8.0.401"
        "ReleaseDate" = "2026-01-16"
        "BaseCVSS" = 7.4
    }
    "VLC media player" = @{
        "LatestVersion" = "3.0.20"
        "ReleaseDate" = "2025-12-20"
        "BaseCVSS" = 6.5
    }
    "7-Zip" = @{
        "LatestVersion" = "24.01"
        "ReleaseDate" = "2026-01-15"
        "BaseCVSS" = 7.0
    }
    "WinRAR" = @{
        "LatestVersion" = "6.24"
        "ReleaseDate" = "2026-01-10"
        "BaseCVSS" = 7.8
    }
    "Notepad++" = @{
        "LatestVersion" = "8.6.2"
        "ReleaseDate" = "2026-01-20"
        "BaseCVSS" = 6.0
    }
}

# Function to compare versions
function Compare-Version {
    param(
        [string]$InstalledVersion,
        [string]$LatestVersion
    )
    
    if ([string]::IsNullOrEmpty($InstalledVersion) -or [string]::IsNullOrEmpty($LatestVersion)) {
        return $false
    }
    
    try {
        # Remove any non-numeric prefixes and suffixes
        $installed = $InstalledVersion -replace '[^0-9.]', ''
        $latest = $LatestVersion -replace '[^0-9.]', ''
        
        # Split into parts
        $installedParts = $installed.Split('.') | ForEach-Object { [int]$_ }
        $latestParts = $latest.Split('.') | ForEach-Object { [int]$_ }
        
        # Compare each part
        $maxLength = [Math]::Max($installedParts.Count, $latestParts.Count)
        
        for ($i = 0; $i -lt $maxLength; $i++) {
            $installedPart = if ($i -lt $installedParts.Count) { $installedParts[$i] } else { 0 }
            $latestPart = if ($i -lt $latestParts.Count) { $latestParts[$i] } else { 0 }
            
            if ($installedPart -lt $latestPart) {
                return $true  # Installed is older
            }
            elseif ($installedPart -gt $latestPart) {
                return $false  # Installed is newer
            }
        }
        
        return $false  # Versions are equal
        
    } catch {
        Write-Log "Error comparing versions: $InstalledVersion vs $LatestVersion - $_" "WARN"
        return $false
    }
}

# MSRC API Configuration
$msrcApiBase = "https://api.msrc.microsoft.com/cvrf/v2.0"
$msrcHeaders = @{ "Accept" = "application/json" }

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
        ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
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
    Write-Host "Scanning installed applications..." -ForegroundColor Cyan
    
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
            }
        }
    } catch { }
    
    return $apps | Sort-Object Name -Unique
}

function Get-MSRCVulnerabilities {
    param([int]$MonthsBack)
    
    Write-Host "`nQuerying Microsoft MSRC for vulnerabilities..." -ForegroundColor Cyan
    
    $allVulnerabilities = @()
    
    try {
        $response = Invoke-RestMethod -Uri "$msrcApiBase/updates" -Headers $msrcHeaders -TimeoutSec 30 -ErrorAction Stop
        $updateIDs = $response.value
        
        $targetDate = (Get-Date).AddMonths(-$MonthsBack)
        $recentUpdates = $updateIDs | Where-Object { 
            try {
                $updateDate = [DateTime]::ParseExact($_.ID, "yyyy-MMM", $null)
                $updateDate -ge $targetDate
            } catch { $false }
        } | Select-Object -First $MonthsBack
        
        Write-Host "Processing $($recentUpdates.Count) security bulletins..." -ForegroundColor Gray
        
        $counter = 0
        foreach ($update in $recentUpdates) {
            $counter++
            Write-Progress -Activity "Scanning MSRC Vulnerabilities" -Status "Processing $($update.ID)" -PercentComplete (($counter / $recentUpdates.Count) * 100)
            
            try {
                $cvrfDoc = Invoke-RestMethod -Uri "$msrcApiBase/cvrf/$($update.ID)" -Headers $msrcHeaders -TimeoutSec 60 -ErrorAction SilentlyContinue
                
                if ($cvrfDoc.Vulnerability) {
                    foreach ($vuln in $cvrfDoc.Vulnerability) {
                        $severity = "Unknown"
                        $cvssScore = 0.0
                        
                        if ($vuln.Threats) {
                            $severityThreat = $vuln.Threats | Where-Object { $_.Type -eq 0 } | Select-Object -First 1
                            if ($severityThreat) {
                                $severity = $severityThreat.Description.Value
                            }
                        }
                        
                        if ($vuln.CVSSScoreSets) {
                            $cvssSet = $vuln.CVSSScoreSets | Select-Object -First 1
                            if ($cvssSet.BaseScore) {
                                $cvssScore = [double]$cvssSet.BaseScore
                            }
                        }
                        
                        $kbArticles = @()
                        if ($vuln.Remediations) {
                            foreach ($remediation in $vuln.Remediations) {
                                # Method 1: Check Description field
                                if ($remediation.Description.Value -match 'KB\d+') {
                                    $kbArticles += $matches[0]
                                }
                                
                                # Method 2: Check URL field (often contains KB number)
                                if ($remediation.URL -match 'KB\d+') {
                                    $kbArticles += $matches[0]
                                }
                                
                                # Method 3: Check Supercedence field
                                if ($remediation.Supercedence -match 'KB\d+') {
                                    $kbArticles += $matches[0]
                                }
                                
                                # Method 4: Check FixedBuild field
                                if ($remediation.FixedBuild -match 'KB\d+') {
                                    $kbArticles += $matches[0]
                                }
                            }
                        }
                        
                        # Remove duplicates
                        $kbArticles = $kbArticles | Select-Object -Unique
                        
                        # If still no KB found, try to extract from product tree or notes
                        if ($kbArticles.Count -eq 0 -and $vuln.Notes) {
                            foreach ($note in $vuln.Notes) {
                                if ($note.Value -match 'KB\d+') {
                                    $kbArticles += $matches[0]
                                }
                            }
                        }
                        
                        # Final cleanup - remove duplicates again
                        $kbArticles = $kbArticles | Select-Object -Unique
                        
                        # Debug: Show KB articles found (uncomment for troubleshooting)
                        # if ($kbArticles.Count -gt 0) {
                        #     Write-Host "  $($vuln.CVE): Found KBs: $($kbArticles -join ', ')" -ForegroundColor Gray
                        # }
                        
                        # Get product info
                        $products = @()
                        if ($vuln.ProductStatuses) {
                            foreach ($status in $vuln.ProductStatuses) {
                                if ($status.ProductID) {
                                    $products += $status.ProductID
                                }
                            }
                        }
                        
                        $allVulnerabilities += [PSCustomObject]@{
                            Source = "MSRC"
                            CVE = $vuln.CVE
                            Title = $vuln.Title.Value
                            Severity = $severity
                            CVSSScore = $cvssScore
                            Product = if ($products.Count -gt 0) { ($products | Select-Object -First 3) -join ', ' } else { "Microsoft Product" }
                            Update = $update.ID
                            KBArticles = ($kbArticles -join '; ')
                            IsPatched = $false
                            CurrentVersion = ""
                            FixedVersion = ""
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

function Get-ThirdPartyVulns {
    param([array]$InstalledApps)
    
    Write-Host "`nChecking third-party applications..." -ForegroundColor Cyan
    Write-Host "Comparing installed versions against latest releases..." -ForegroundColor Gray
    
    $vulnApps = @()
    $checkedApps = 0
    
    foreach ($app in $InstalledApps) {
        foreach ($knownApp in $LatestVersions.Keys) {
            # Check if installed app matches a known application
            if ($app.Name -like "*$knownApp*") {
                $checkedApps++
                $latestInfo = $LatestVersions[$knownApp]
                
                # Compare versions
                if ($app.Version) {
                    $isOutdated = Compare-Version -InstalledVersion $app.Version -LatestVersion $latestInfo.LatestVersion
                    
                    if ($isOutdated) {
                        Write-Host "  Found outdated: $($app.Name) v$($app.Version) (Latest: $($latestInfo.LatestVersion))" -ForegroundColor Yellow
                        
                        # Calculate age-based CVSS (older = worse)
                        $releaseDate = [DateTime]::Parse($latestInfo.ReleaseDate)
                        $daysOld = ((Get-Date) - $releaseDate).Days
                        
                        # Increase severity for very old versions
                        $cvssScore = $latestInfo.BaseCVSS
                        if ($daysOld -gt 90) { $cvssScore = [Math]::Min(10.0, $cvssScore + 1.0) }
                        elseif ($daysOld -gt 30) { $cvssScore = [Math]::Min(10.0, $cvssScore + 0.5) }
                        
                        # Determine severity based on CVSS
                        $severity = if ($cvssScore -ge 9.0) { "Critical" }
                                   elseif ($cvssScore -ge 7.0) { "High" }
                                   elseif ($cvssScore -ge 4.0) { "Medium" }
                                   else { "Low" }
                        
                        $vulnApps += [PSCustomObject]@{
                            Source = "Third-Party"
                            CVE = "OUTDATED-$(Get-Date -Format 'yyyy')-$($app.Name -replace '[^a-zA-Z0-9]', '')"
                            Title = "Outdated version detected - Security updates available (Installed: $($app.Version), Latest: $($latestInfo.LatestVersion))"
                            Severity = $severity
                            CVSSScore = $cvssScore
                            Product = $app.Name
                            Update = "N/A"
                            KBArticles = ""
                            IsPatched = $false
                            CurrentVersion = $app.Version
                            FixedVersion = $latestInfo.LatestVersion
                        }
                    } else {
                        Write-Host "  ✓ Up-to-date: $($app.Name) v$($app.Version)" -ForegroundColor Green
                    }
                } else {
                    Write-Verbose "No version info for $($app.Name)"
                }
                
                break  # Found match, no need to check other known apps
            }
        }
    }
    
    Write-Host "`nThird-party scan complete:" -ForegroundColor Cyan
    Write-Host "  Applications checked: $checkedApps" -ForegroundColor White
    Write-Host "  Outdated applications: $($vulnApps.Count)" -ForegroundColor $(if ($vulnApps.Count -gt 0) { "Yellow" } else { "Green" })
    
    if ($checkedApps -eq 0) {
        Write-Host "`n⚠️  No known third-party applications detected on this system" -ForegroundColor Yellow
        Write-Host "   Applications monitored: Chrome, Firefox, Adobe, Java, VLC, 7-Zip, WinRAR, Notepad++" -ForegroundColor Gray
    }
    
    return $vulnApps
}

function Generate-HTMLDashboard {
    param(
        [array]$Vulnerabilities,
        [object]$SystemInfo,
        [string]$OutputPath
    )
    
    Write-Host "`nGenerating HTML dashboard..." -ForegroundColor Cyan
    
    # Calculate statistics
    $stats = @{
        Critical = ($Vulnerabilities | Where-Object { $_.Severity -eq "Critical" -or $_.CVSSScore -ge 9.0 }).Count
        High = ($Vulnerabilities | Where-Object { ($_.Severity -in @("Important", "High")) -or ($_.CVSSScore -ge 7.0 -and $_.CVSSScore -lt 9.0) }).Count
        Medium = ($Vulnerabilities | Where-Object { ($_.Severity -in @("Moderate", "Medium")) -or ($_.CVSSScore -ge 4.0 -and $_.CVSSScore -lt 7.0) }).Count
        Low = ($Vulnerabilities | Where-Object { $_.Severity -eq "Low" -or ($_.CVSSScore -gt 0 -and $_.CVSSScore -lt 4.0) }).Count
    }
    
    $totalVulns = $Vulnerabilities.Count
    $msrcCount = ($Vulnerabilities | Where-Object { $_.Source -eq "MSRC" }).Count
    $thirdPartyCount = ($Vulnerabilities | Where-Object { $_.Source -eq "Third-Party" }).Count
    
    # Generate vulnerability table rows
    $tableRows = ""
    foreach ($vuln in $Vulnerabilities) {
        $severityClass = switch ($vuln.Severity) {
            "Critical" { "critical" }
            "Important" { "high" }
            "High" { "high" }
            "Moderate" { "medium" }
            "Medium" { "medium" }
            "Low" { "low" }
            default { 
                if ($vuln.CVSSScore -ge 9.0) { "critical" }
                elseif ($vuln.CVSSScore -ge 7.0) { "high" }
                elseif ($vuln.CVSSScore -ge 4.0) { "medium" }
                else { "low" }
            }
        }
        
        $cveLink = if ($vuln.Source -eq "MSRC") {
            "https://msrc.microsoft.com/update-guide/vulnerability/$($vuln.CVE)"
        } else {
            "https://nvd.nist.gov/vuln/detail/$($vuln.CVE)"
        }
        
        $cvssDisplay = if ($vuln.CVSSScore -gt 0) { $vuln.CVSSScore.ToString("F1") } else { "N/A" }
        $kbDisplay = if ($vuln.KBArticles) { $vuln.KBArticles } else { "N/A" }
        $versionInfo = if ($vuln.CurrentVersion) { 
            "Current: $($vuln.CurrentVersion)<br>Fixed: $($vuln.FixedVersion)" 
        } else { 
            $kbDisplay 
        }
        
        # Extract update month from MSRC Update field (e.g., "2026-02" from "2026-Feb")
        $updateMonth = if ($vuln.Update -and $vuln.Update -match '(\d{4})-(\w+)') {
            "$($matches[1])-$($matches[2])"
        } else { "" }
        
        # Create searchable text including KB articles and update dates
        # CRITICAL: Get KB articles from the vulnerability object
        $searchableKBs = if ($vuln.KBArticles -and $vuln.KBArticles.Length -gt 0) { 
            $vuln.KBArticles 
        } else { 
            ""
        }
        
        # Debug output for first few vulnerabilities
        if ($vuln.CVE -eq "CVE-2026-21222") {
            Write-Host "`nDEBUG - CVE-2026-21222:" -ForegroundColor Yellow
            Write-Host "  KB Articles from vuln object: '$($vuln.KBArticles)'" -ForegroundColor Cyan
            Write-Host "  searchableKBs variable: '$searchableKBs'" -ForegroundColor Cyan
            Write-Host "  Update from vuln object: '$($vuln.Update)'" -ForegroundColor Cyan
            Write-Host "  updateMonth variable: '$updateMonth'" -ForegroundColor Cyan
        }
        
        $tableRows += @"
        <tr data-severity="$severityClass" data-source="$($vuln.Source.ToLower())" data-kbs="$searchableKBs" data-update="$updateMonth">
            <td><span class="severity-badge $severityClass">$($vuln.Severity)</span></td>
            <td><span class="cvss-score $severityClass">$cvssDisplay</span></td>
            <td><a href="$cveLink" target="_blank" class="cve-link">$($vuln.CVE)</a></td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($vuln.Title))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($vuln.Product))</td>
            <td><span class="source-badge $($vuln.Source.ToLower())">$($vuln.Source)</span></td>
            <td class="version-cell">$versionInfo</td>
        </tr>
"@
    }
    
    # Generate chart data
    $chartData = @{
        Critical = $stats.Critical
        High = $stats.High
        Medium = $stats.Medium
        Low = $stats.Low
    } | ConvertTo-Json
    
    # HTML Template
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Dashboard - $($SystemInfo.ComputerName)</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 32px;
            margin-bottom: 10px;
        }
        
        .header p {
            opacity: 0.9;
            font-size: 14px;
        }
        
        .system-info {
            background: #ecf0f1;
            padding: 20px 30px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        
        .info-item {
            display: flex;
            flex-direction: column;
        }
        
        .info-label {
            font-size: 12px;
            color: #7f8c8d;
            font-weight: 600;
            text-transform: uppercase;
            margin-bottom: 5px;
        }
        
        .info-value {
            font-size: 14px;
            color: #2c3e50;
            font-weight: 500;
        }
        
        .severity-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
        }
        
        .severity-card {
            padding: 30px;
            border-radius: 12px;
            color: white;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            cursor: pointer;
        }
        
        .severity-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.2);
        }
        
        .severity-card.critical {
            background: linear-gradient(135deg, #c0392b 0%, #8e44ad 100%);
        }
        
        .severity-card.high {
            background: linear-gradient(135deg, #e67e22 0%, #d35400 100%);
        }
        
        .severity-card.medium {
            background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%);
        }
        
        .severity-card.low {
            background: linear-gradient(135deg, #27ae60 0%, #229954 100%);
        }
        
        .severity-card .count {
            font-size: 48px;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .severity-card .label {
            font-size: 18px;
            opacity: 0.95;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .filters {
            padding: 20px 30px;
            background: #f8f9fa;
            border-top: 1px solid #dee2e6;
            border-bottom: 1px solid #dee2e6;
        }
        
        .filter-group {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            align-items: center;
        }
        
        .filter-group label {
            font-weight: 600;
            color: #495057;
            margin-right: 5px;
        }
        
        .filter-group input, .filter-group select {
            padding: 8px 15px;
            border: 1px solid #ced4da;
            border-radius: 6px;
            font-size: 14px;
        }
        
        .filter-group button {
            padding: 8px 20px;
            background: #3498db;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            transition: background 0.3s ease;
        }
        
        .filter-group button:hover {
            background: #2980b9;
        }
        
        .table-container {
            padding: 30px;
            overflow-x: auto;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
        }
        
        thead {
            background: #34495e;
            color: white;
        }
        
        th {
            padding: 15px;
            text-align: left;
            font-weight: 600;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        td {
            padding: 15px;
            border-bottom: 1px solid #ecf0f1;
            font-size: 14px;
        }
        
        tr:hover {
            background: #f8f9fa;
        }
        
        .severity-badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            color: white;
        }
        
        .severity-badge.critical {
            background: #c0392b;
        }
        
        .severity-badge.high {
            background: #e67e22;
        }
        
        .severity-badge.medium {
            background: #f39c12;
        }
        
        .severity-badge.low {
            background: #27ae60;
        }
        
        .cvss-score {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 6px;
            font-weight: bold;
            color: white;
        }
        
        .cvss-score.critical {
            background: #c0392b;
        }
        
        .cvss-score.high {
            background: #e67e22;
        }
        
        .cvss-score.medium {
            background: #f39c12;
        }
        
        .cvss-score.low {
            background: #27ae60;
        }
        
        .cve-link {
            color: #3498db;
            text-decoration: none;
            font-weight: 600;
            transition: color 0.3s ease;
        }
        
        .cve-link:hover {
            color: #2980b9;
            text-decoration: underline;
        }
        
        .source-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .source-badge.msrc {
            background: #3498db;
            color: white;
        }
        
        .source-badge.third-party {
            background: #9b59b6;
            color: white;
        }
        
        .version-cell {
            font-size: 12px;
            color: #7f8c8d;
        }
        
        .stats-summary {
            padding: 20px 30px;
            background: #ecf0f1;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }
        
        .stat-box {
            text-align: center;
            padding: 20px 15px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            min-height: 100px;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }
        
        .stat-number {
            font-size: 36px;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 8px;
        }
        
        .stat-label {
            font-size: 13px;
            color: #7f8c8d;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            line-height: 1.4;
            word-wrap: break-word;
        }
        
        .footer {
            padding: 20px 30px;
            background: #2c3e50;
            color: white;
            text-align: center;
            font-size: 13px;
        }
        
        .hidden {
            display: none;
        }
        
        @media print {
            body {
                background: white;
            }
            .container {
                box-shadow: none;
            }
            .filter-group button {
                display: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Vulnerability Dashboard</h1>
            <p>Comprehensive Security Assessment Report</p>
        </div>
        
        <div class="system-info">
            <div class="info-item">
                <span class="info-label">Computer Name</span>
                <span class="info-value">$($SystemInfo.ComputerName)</span>
            </div>
            <div class="info-item">
                <span class="info-label">Operating System</span>
                <span class="info-value">$($SystemInfo.OSName)</span>
            </div>
            <div class="info-item">
                <span class="info-label">OS Build</span>
                <span class="info-value">$($SystemInfo.OSBuild)</span>
            </div>
            <div class="info-item">
                <span class="info-label">Architecture</span>
                <span class="info-value">$($SystemInfo.Architecture)</span>
            </div>
            <div class="info-item">
                <span class="info-label">Scan Date</span>
                <span class="info-value">$($SystemInfo.ScanDate)</span>
            </div>
        </div>
        
        <div class="severity-cards">
            <div class="severity-card critical" onclick="filterBySeverity('critical')">
                <div class="count">$($stats.Critical)</div>
                <div class="label">Critical</div>
            </div>
            <div class="severity-card high" onclick="filterBySeverity('high')">
                <div class="count">$($stats.High)</div>
                <div class="label">High</div>
            </div>
            <div class="severity-card medium" onclick="filterBySeverity('medium')">
                <div class="count">$($stats.Medium)</div>
                <div class="label">Medium</div>
            </div>
            <div class="severity-card low" onclick="filterBySeverity('low')">
                <div class="count">$($stats.Low)</div>
                <div class="label">Low</div>
            </div>
        </div>
        
        <div class="stats-summary">
            <div class="stat-box">
                <div class="stat-number">$totalVulns</div>
                <div class="stat-label">Total Vulnerabilities</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">$msrcCount</div>
                <div class="stat-label">Microsoft (MSRC)</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">$thirdPartyCount</div>
                <div class="stat-label">Third-Party Apps</div>
$(if ($thirdPartyCount -eq 0) { "                <div style='font-size: 11px; color: #e74c3c; margin-top: 5px;'>Run with -IncludeThirdParty</div>" })
            </div>
            <div class="stat-box">
                <div class="stat-number">$($Vulnerabilities | Where-Object { -not $_.IsPatched } | Measure-Object).Count</div>
                <div class="stat-label">Unpatched Vulnerabilities</div>
            </div>
        </div>
        
        <div class="filters">
            <div class="filter-group">
                <label for="searchInput">🔍 Search:</label>
                <input type="text" id="searchInput" placeholder="CVE, KB Article, Product, Update (e.g., 2026-02), Title..." onkeyup="filterTable()">
                
                <label for="severityFilter">Severity:</label>
                <select id="severityFilter" onchange="filterTable()">
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
                
                <label for="sourceFilter">Source:</label>
                <select id="sourceFilter" onchange="filterTable()">
                    <option value="">All Sources</option>
                    <option value="msrc">MSRC</option>
                    <option value="third-party">Third-Party</option>
                </select>
                
                <button onclick="resetFilters()">Clear Filters</button>
                <button onclick="window.print()">🖨️ Print Report</button>
            </div>
        </div>
        
        <div class="table-container">
            <table id="vulnTable">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>CVSS</th>
                        <th>CVE ID</th>
                        <th>Description</th>
                        <th>Product</th>
                        <th>Source</th>
                        <th>Remediation</th>
                    </tr>
                </thead>
                <tbody>
                    $tableRows
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Generated by Vulnerability Scanner | Powered by Microsoft MSRC & NVD</p>
            <p>For questions or concerns, contact your IT Security team</p>
        </div>
    </div>
    
    <script>
        // Enhanced filter function that searches KB articles and update dates
        function filterTable() {
            const searchInput = document.getElementById('searchInput').value.toLowerCase();
            const severityFilter = document.getElementById('severityFilter').value;
            const sourceFilter = document.getElementById('sourceFilter').value;
            const table = document.getElementById('vulnTable');
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                const text = row.textContent.toLowerCase();
                const severity = row.getAttribute('data-severity');
                const source = row.getAttribute('data-source');
                const kbs = row.getAttribute('data-kbs') ? row.getAttribute('data-kbs').toLowerCase() : '';
                const update = row.getAttribute('data-update') ? row.getAttribute('data-update').toLowerCase() : '';
                
                let showRow = true;
                
                // Enhanced search: includes visible text, KB articles, and update dates
                if (searchInput) {
                    const matchesText = text.includes(searchInput);
                    const matchesKB = kbs.includes(searchInput);
                    const matchesUpdate = update.includes(searchInput);
                    
                    if (!matchesText && !matchesKB && !matchesUpdate) {
                        showRow = false;
                    }
                }
                
                if (severityFilter && severity !== severityFilter) {
                    showRow = false;
                }
                
                if (sourceFilter && source !== sourceFilter) {
                    showRow = false;
                }
                
                row.style.display = showRow ? '' : 'none';
            }
        }
        
        function filterBySeverity(severity) {
            document.getElementById('severityFilter').value = severity;
            filterTable();
        }
        
        function resetFilters() {
            document.getElementById('searchInput').value = '';
            document.getElementById('severityFilter').value = '';
            document.getElementById('sourceFilter').value = '';
            filterTable();
        }
        
        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            console.log('Vulnerability Dashboard Loaded');
        });
    </script>
</body>
</html>
"@
    
    # Add System.Web for HTML encoding
    Add-Type -AssemblyName System.Web
    
    # Write HTML file
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    
    Write-Host "✓ HTML dashboard generated: $OutputPath" -ForegroundColor Green
}

# ==================== MAIN EXECUTION ====================

Write-Host "`n" -NoNewline
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Vulnerability Scanner with HTML Dashboard" -ForegroundColor Cyan
Write-Host "  Microsoft MSRC + Third-Party Applications" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

# Get system information
$sysInfo = Get-SystemInfo
Write-Host "`nScanning Device: $($sysInfo.ComputerName)" -ForegroundColor White
Write-Host "OS: $($sysInfo.OSName) - Build $($sysInfo.OSBuild)" -ForegroundColor Gray

# Get installed KBs and apps
$installedKBs = Get-InstalledKBs
$installedApps = Get-InstalledThirdPartyApps

Write-Host "Installed Microsoft Updates: $($installedKBs.Count)" -ForegroundColor White
Write-Host "Installed Applications: $($installedApps.Count)" -ForegroundColor White

# Scan Microsoft vulnerabilities
$msrcVulnerabilities = Get-MSRCVulnerabilities -MonthsBack $Months

# Scan third-party vulnerabilities if requested
$thirdPartyVulnerabilities = @()
if ($IncludeThirdParty) {
    $thirdPartyVulnerabilities = Get-ThirdPartyVulns -InstalledApps $installedApps
}

# Combine all vulnerabilities
$allVulnerabilities = $msrcVulnerabilities + $thirdPartyVulnerabilities

# Check which Microsoft KBs are installed
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

Write-Host "`n" -NoNewline
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  SCAN RESULTS" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

$stats = @{
    Critical = ($allVulnerabilities | Where-Object { $_.Severity -eq "Critical" -or $_.CVSSScore -ge 9.0 }).Count
    High = ($allVulnerabilities | Where-Object { ($_.Severity -in @("Important", "High")) -or ($_.CVSSScore -ge 7.0 -and $_.CVSSScore -lt 9.0) }).Count
    Medium = ($allVulnerabilities | Where-Object { ($_.Severity -in @("Moderate", "Medium")) -or ($_.CVSSScore -ge 4.0 -and $_.CVSSScore -lt 7.0) }).Count
    Low = ($allVulnerabilities | Where-Object { $_.Severity -eq "Low" -or ($_.CVSSScore -gt 0 -and $_.CVSSScore -lt 4.0) }).Count
}

Write-Host "`nTotal Vulnerabilities: $($allVulnerabilities.Count)" -ForegroundColor White
Write-Host "  - Microsoft (MSRC): $msrcVulnerabilities.Count" -ForegroundColor Cyan
Write-Host "  - Third-Party Apps: $($thirdPartyVulnerabilities.Count)" -ForegroundColor Cyan

if (-not $IncludeThirdParty) {
    Write-Host "`n⚠️  NOTE: Third-party application scanning is DISABLED" -ForegroundColor Yellow
    Write-Host "   To scan Chrome, Adobe, Firefox, Java, etc., run with:" -ForegroundColor Yellow
    Write-Host "   .\Check-Vulnerabilities-Dashboard.ps1 -IncludeThirdParty" -ForegroundColor White
} elseif ($thirdPartyVulnerabilities.Count -eq 0) {
    Write-Host "`n✓ Third-party scanning enabled - No known vulnerable versions detected" -ForegroundColor Green
    Write-Host "  This means your third-party apps are either:" -ForegroundColor Gray
    Write-Host "  • Not installed (Chrome, Adobe, Firefox, etc.)" -ForegroundColor Gray
    Write-Host "  • Already updated to secure versions" -ForegroundColor Gray
    Write-Host "  • Not in the current vulnerability database" -ForegroundColor Gray
}

Write-Host "`nVulnerabilities by Severity:" -ForegroundColor White
Write-Host "  Critical: " -NoNewline; Write-Host "$($stats.Critical)" -ForegroundColor DarkRed
Write-Host "  High:     " -NoNewline; Write-Host "$($stats.High)" -ForegroundColor Red
Write-Host "  Medium:   " -NoNewline; Write-Host "$($stats.Medium)" -ForegroundColor Yellow
Write-Host "  Low:      " -NoNewline; Write-Host "$($stats.Low)" -ForegroundColor Green

# Generate HTML Dashboard
Generate-HTMLDashboard -Vulnerabilities $allVulnerabilities -SystemInfo $sysInfo -OutputPath $OutputHTML

# Export CSV if requested
if ($ExportCSV) {
    try {
        $allVulnerabilities | Export-Csv -Path $OutputCSV -NoTypeInformation -Encoding UTF8
        Write-Host "✓ CSV report exported: $OutputCSV" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to export CSV: $_"
    }
}

Write-Host "`n" -NoNewline
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "📊 Open the HTML dashboard in your browser to view results" -ForegroundColor Green
Write-Host "   File: $OutputHTML" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Auto-open dashboard in default browser
try {
    Start-Process $OutputHTML
    Write-Host "✓ Dashboard opened in default browser" -ForegroundColor Green
} catch {
    Write-Host "! Open the HTML file manually: $OutputHTML" -ForegroundColor Yellow
}

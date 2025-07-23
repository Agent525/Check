#Requires -RunAsAdministrator

# Clear the terminal and create SS folder silently
Clear-Host
$ssPath = "C:\SS"
if (-not (Test-Path $ssPath)) {
    New-Item -ItemType Directory -Path $ssPath -Force | Out-Null
}

# Import ASCII art from Art.ps1
$art = @"
 .d888888  888888ba  d888888P dP           888888ba  dP    dP  888888ba   .d888888  .d88888b  .d88888b  
d8'    88  88    ``8b    88    88           88    ``8b Y8.  .8P  88    ``8b d8'    88  88.    "' 88.    "' 
88aaaaa88a 88     88    88    88          a88aaaa8P'  Y8aa8P  a88aaaa8P' 88aaaaa88a ``Y88888b. ``Y88888b. 
88     88  88     88    88    88 88888888  88   ``8b.    88     88        88     88        ``8b       ``8b 
88     88  88     88    88    88           88    .88    88     88        88     88  d8'   .8P d8'   .8P 
88     88  dP     dP    dP    dP           88888888P    dP     dP        88     88   Y88888P   Y88888P  
"@

# Display ASCII art with red fade colors
$colors = @("DarkRed", "Red", "Magenta")
$lines = $art.Split([System.Environment]::NewLine, [System.StringSplitOptions]::RemoveEmptyEntries)

foreach ($line in $lines) {
    $colorIndex = 0
    foreach ($char in $line.ToCharArray()) {
        if ($char -match '\s') {
            Write-Host $char -NoNewline
        } else {
            Write-Host $char -ForegroundColor $colors[$colorIndex] -NoNewline
            $colorIndex = ($colorIndex + 1) % $colors.Count
        }
    }
    Write-Host
}

Write-Host "`nWhat actions would you like to perform?" -ForegroundColor Yellow
Write-Host ""
Write-Host "[1] Download PC Check Tools Downloader" -ForegroundColor Green
Write-Host "[2] Download Moss File Checker" -ForegroundColor Green
Write-Host "[3] Run Generic Analysis" -ForegroundColor Green
Write-Host "[4] Delete Previous Filebin" -ForegroundColor Red
Write-Host ""

do {
    $choice = Read-Host "Enter your choice (1-4)"
    
    switch ($choice) {
        "1" {
            Write-Host "`nDownloading PC Check Tools Downloader..." -ForegroundColor Yellow
            try {
                $downloadPath = Join-Path $ssPath "TechTool.exe"
                Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Agent525/Check/refs/heads/main/TechTool.exe" -OutFile $downloadPath
                Write-Host "Downloaded successfully to: $downloadPath" -ForegroundColor Green
            } catch {
                Write-Host "Failed to download: $($_.Exception.Message)" -ForegroundColor Red
            }
            Write-Host "Press any key to return to menu..." -ForegroundColor Yellow
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Clear-Host
            & "$PSCommandPath"  # Restart the script
            return
        }
        "2" {
            Write-Host "`nDownloading Moss File Checker..." -ForegroundColor Yellow
            try {
                $downloadPath = Join-Path $ssPath "MossCheck.cmd"
                Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Agent525/Check/refs/heads/main/MossCheck.cmd" -OutFile $downloadPath
                Write-Host "Downloaded successfully to: $downloadPath" -ForegroundColor Green
            } catch {
                Write-Host "Failed to download: $($_.Exception.Message)" -ForegroundColor Red
            }
            Write-Host "Press any key to return to menu..." -ForegroundColor Yellow
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Clear-Host
            & $PSCommandPath  # Restart the script
            return
        }
        "3" {
            Write-Host "`nStarting Generic Analysis..." -ForegroundColor Green
            break
        }
        "4" {
            Write-Host "`nDelete Previous Filebin" -ForegroundColor Red
            Write-Host "Current system bin name: PCCHECK$env:COMPUTERNAME" -ForegroundColor Cyan
            Write-Host ""
            $binName = Read-Host "Enter the bin name to delete"
            
            if ($binName) {
                Write-Host "`nDeleting filebin: $binName..." -ForegroundColor Yellow
                try {
                    $deleteUrl = "https://filebin.net/$binName"
                    $curlDeleteArgs = @(
                        '-X', 'DELETE',
                        $deleteUrl,
                        '-H', 'accept: application/json'
                    )
                    
                    $deleteResult = & curl @curlDeleteArgs 2>&1
                    
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "Filebin deleted successfully!" -ForegroundColor Green
                    } else {
                        Write-Host "Delete failed. Error: $deleteResult" -ForegroundColor Red
                    }
                } catch {
                    Write-Host "Delete failed. Error: $($_.Exception.Message)" -ForegroundColor Red
                }
            } else {
                Write-Host "No bin name provided." -ForegroundColor Red
            }
            
            Write-Host "Press any key to return to menu..." -ForegroundColor Yellow
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Clear-Host
            & $PSCommandPath  # Restart the script
            return
        }
        default {
            Write-Host "Invalid choice. Please enter 1, 2, 3, or 4." -ForegroundColor Red
        }
    }
} while ($choice -notin @("1", "2", "3", "4"))

# Initialize progress tracking
$totalSections = 14
$currentSection = 0

function Update-Progress {
    param($ActivityName)
    $script:currentSection++
    $percentComplete = ($script:currentSection / $totalSections) * 100
    Write-Progress -Activity "Security Analysis" -Status $ActivityName -PercentComplete $percentComplete
}

# Create findings file with timestamp
$timestamp = Get-Date -Format "MM-dd"
$findingsFile = Join-Path $ssPath "Findings$timestamp.txt"

Update-Progress "Initializing system information..."

# Initialize findings file with basic info
$content = @"
Security Analysis Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") $(Get-TimeZone | Select-Object -ExpandProperty Id)
Current User: $env:USERNAME
OS Install Date: $((Get-CimInstance Win32_OperatingSystem).InstallDate)

"@

Add-Content -Path $findingsFile -Value $content

# Check Secure Boot
try {
    $secureBoot = Confirm-SecureBootUEFI
    $secureBootStatus = "Secure Boot: Enabled"
} catch {
    $secureBootStatus = "Secure Boot: Disabled or Not Supported"
}
Add-Content -Path $findingsFile -Value $secureBootStatus

# Check Kernel DMA Protection
try {
    $deviceGuardProps = Get-ComputerInfo | Select-Object -ExpandProperty DeviceGuardAvailableSecurityProperties
    if ($deviceGuardProps -contains "DMA Protection") {
        $dmaStatus = "Kernel DMA Protection: Available/Enabled"
    } else {
        $dmaStatus = "Kernel DMA Protection: Not Available/Disabled"
    }
} catch {
    $dmaStatus = "Kernel DMA Protection: Unable to determine"
}
Add-Content -Path $findingsFile -Value $dmaStatus

# Check Virtualization
try {
    $virtualization = Get-CimInstance Win32_ComputerSystem
    $virtStatus = "Virtualization: $($virtualization.HypervisorPresent)"
} catch {
    $virtStatus = "Virtualization: Unable to determine"
}
Add-Content -Path $findingsFile -Value $virtStatus

# Function to add section separator
function Add-Section {
    param($SectionName)
    $separator = @"

===================
$SectionName
===================
"@
    Add-Content -Path $findingsFile -Value $separator
}

# Function to check if file is digitally signed
function Test-FileSignature {
    param($FilePath)
    try {
        if (Test-Path $FilePath) {
            $signature = Get-AuthenticodeSignature $FilePath -ErrorAction SilentlyContinue
            return $signature.Status -eq "Valid"
        }
    } catch {
        return $false
    }
    return $false
}

Update-Progress "Enumerating drive letters..."

# Drive Letters
Add-Section "Drive Letters"
Get-WmiObject Win32_LogicalDisk | ForEach-Object {
    Add-Content -Path $findingsFile -Value "Drive $($_.DeviceID) - $($_.VolumeName) ($($_.DriveType))"
}

Update-Progress "Enumerating USB devices..."

# USB Devices
Add-Section "USB Devices"
try {
    Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 } | ForEach-Object {
        Add-Content -Path $findingsFile -Value "USB Drive: $($_.DeviceID) - $($_.VolumeName)"
    }
    
    Get-WmiObject Win32_USBHub | ForEach-Object {
        Add-Content -Path $findingsFile -Value "USB Hub: $($_.Name) - $($_.DeviceID)"
    }
} catch {
    Add-Content -Path $findingsFile -Value "Unable to enumerate USB devices"
}

Update-Progress "Detecting installed browsers..."

# Browser Detection
Add-Section "Installed Browsers"
$browserPaths = @{
    "Chrome" = @("${env:ProgramFiles}\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe")
    "Firefox" = @("${env:ProgramFiles}\Mozilla Firefox\firefox.exe", "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe")
    "Edge" = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe")
    "Opera" = @("${env:ProgramFiles}\Opera\opera.exe", "${env:ProgramFiles(x86)}\Opera\opera.exe")
    "Brave" = @("${env:ProgramFiles}\BraveSoftware\Brave-Browser\Application\brave.exe", "${env:ProgramFiles(x86)}\BraveSoftware\Brave-Browser\Application\brave.exe")
}

foreach ($browser in $browserPaths.Keys) {
    foreach ($path in $browserPaths[$browser]) {
        if (Test-Path $path) {
            Add-Content -Path $findingsFile -Value "$browser found at: $path"
        }
    }
}

Update-Progress "Scanning Downloads folder..."

# Downloads Check
Add-Section "Downloads"
try {
    $downloadsPath = [Environment]::GetFolderPath("UserProfile") + "\Downloads"
    if (Test-Path $downloadsPath) {
        $downloadResults = @{
            exe = @()
            zip = @()
            rar = @()
        }
        Get-ChildItem $downloadsPath -Recurse | Where-Object { $_.Extension -match "\.(zip|rar|exe)$" } | ForEach-Object {
            if ($_.Extension -eq ".exe" -and -not (Test-FileSignature $_.FullName)) {
                $downloadResults.exe += $_.FullName
            } elseif ($_.Extension -eq ".zip") {
                $downloadResults.zip += $_.FullName
            } elseif ($_.Extension -eq ".rar") {
                $downloadResults.rar += $_.FullName
            }
        }
        # Sort and output by file type
        $downloadResults.exe | Sort-Object { $_.Length } | ForEach-Object { Add-Content -Path $findingsFile -Value $_ }
        $downloadResults.rar | Sort-Object { $_.Length } | ForEach-Object { Add-Content -Path $findingsFile -Value $_ }
        $downloadResults.zip | Sort-Object { $_.Length } | ForEach-Object { Add-Content -Path $findingsFile -Value $_ }
    }
} catch {
    Add-Content -Path $findingsFile -Value "Unable to access Downloads folder"
}

Update-Progress "Analyzing Prefetch files..."

# Prefetch Files
Add-Section "Prefetch Files"
try {
    $prefetchPath = "C:\Windows\Prefetch"
    if (Test-Path $prefetchPath) {
        $prefetchResults = @()
        Get-ChildItem $prefetchPath -Filter "*.pf" | ForEach-Object {
            $prefetchResults += "$($_.Name) - $($_.LastWriteTime)"
        }
        $prefetchResults | Sort-Object | ForEach-Object {
            Add-Content -Path $findingsFile -Value $_
        }
    }
} catch {
    Add-Content -Path $findingsFile -Value "Unable to access Prefetch folder"
}

Update-Progress "Checking MuiCache registry..."

# MuiCache Registry Entries
Add-Section "MuiCache"
try {
    $muiCache = Get-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" -ErrorAction SilentlyContinue
    if ($muiCache) {
        $muiCacheResults = @()
        $muiCache.PSObject.Properties | Where-Object { $_.Name -match "\.exe" -and $_.Name -notmatch "PS" -and $_.Name -notmatch "FriendlyAppName" } | ForEach-Object {
            # Extract path up to .exe
            $exePath = ($_.Name -split '\.exe')[0] + '.exe'
            if (-not (Test-FileSignature $exePath)) {
                $muiCacheResults += $exePath
            }
        }
        $muiCacheResults | Sort-Object { $_.Length } | ForEach-Object {
            Add-Content -Path $findingsFile -Value $_
        }
    }
} catch {
    Add-Content -Path $findingsFile -Value "Unable to access MuiCache registry"
}

Update-Progress "Checking AppSwitched registry..."

# AppSwitched Registry Entries
Add-Section "AppSwitched"
try {
    $appSwitched = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched" -ErrorAction SilentlyContinue
    if ($appSwitched) {
        $appSwitchedResults = @()
        $appSwitched.PSObject.Properties | Where-Object { $_.Name -match "\.exe" -and $_.Name -notmatch "PS" -and $_.Name -match "^[A-Za-z]:\\" } | ForEach-Object {
            if (-not (Test-FileSignature $_.Name)) {
                $appSwitchedResults += $_.Name
            }
        }
        $appSwitchedResults | Sort-Object { $_.Length } | ForEach-Object {
            Add-Content -Path $findingsFile -Value $_
        }
    }
} catch {
    Add-Content -Path $findingsFile -Value "Unable to access AppSwitched registry"
}

Update-Progress "Checking DLL OpenWithList..."

# DLL OpenWithList
Add-Section "DLL OpenWithList"
try {
    $dllOpenWith = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dll\OpenWithList" -ErrorAction SilentlyContinue
    if ($dllOpenWith) {
        $dllOpenWith.PSObject.Properties | Where-Object { $_.Name -notmatch "PS" } | ForEach-Object {
            Add-Content -Path $findingsFile -Value "$($_.Name) = $($_.Value)"
        }
    }
} catch {
    Add-Content -Path $findingsFile -Value "Unable to access DLL OpenWithList registry"
}

Update-Progress "Checking BAM registry..."

# BAM Registry Entries
Add-Section "BAM Registry"
try {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\$currentUser"
    $bamEntries = Get-ItemProperty $bamPath -ErrorAction SilentlyContinue
    if ($bamEntries) {
        $bamResults = @()
        $bamEntries.PSObject.Properties | Where-Object { $_.Name -match "\.exe" -and $_.Name -notmatch "PS" -and $_.Name -match "^[A-Za-z]:\\" } | ForEach-Object {
            if (-not (Test-FileSignature $_.Name)) {
                $bamResults += $_.Name
            }
        }
        $bamResults | Sort-Object { $_.Length } | ForEach-Object {
            Add-Content -Path $findingsFile -Value $_
        }
    }
} catch {
    Add-Content -Path $findingsFile -Value "Unable to access BAM registry"
}

Update-Progress "Checking Compatibility Assistant Store..."

# Compatibility Assistant Store
Add-Section "Compatibility Assistant Store"
try {
    $compatStore = Get-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store" -ErrorAction SilentlyContinue
    if ($compatStore) {
        $compatResults = @()
        $compatStore.PSObject.Properties | Where-Object { $_.Name -match "\.exe" -and $_.Name -notmatch "PS" -and $_.Name -match "^[A-Za-z]:\\" } | ForEach-Object {
            if (-not (Test-FileSignature $_.Name)) {
                $compatResults += $_.Name
            }
        }
        $compatResults | Sort-Object { $_.Length } | ForEach-Object {
            Add-Content -Path $findingsFile -Value $_
        }
    }
} catch {
    Add-Content -Path $findingsFile -Value "Unable to access Compatibility Assistant Store"
}

Update-Progress "Checking deleted files..."

# Deleted Files Check (Recent deletion artifacts)
Add-Section "Recently Deleted Files"
try {
    $deletedResults = @()
    $recycleBin = Get-ChildItem "C:\`$Recycle.Bin" -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match "\.(exe|pf)$" }
    $recycleBin | ForEach-Object {
        $deletedResults += $_.FullName
    }
    $deletedResults | Sort-Object { $_.Length } | ForEach-Object {
        Add-Content -Path $findingsFile -Value $_
    }
} catch {
    Add-Content -Path $findingsFile -Value "Unable to access Recycle Bin"
}

Update-Progress "Finalizing report..."

Write-Progress -Activity "Security Analysis" -Completed
Write-Host "`nAnalysis complete! Results saved to: $findingsFile" -ForegroundColor Green

# Upload to filebin
Write-Host "Uploading findings to filebin..." -ForegroundColor Yellow
try {
    # Get computer name and format date for URL
    $computerName = $env:COMPUTERNAME
    $dateForUrl = Get-Date -Format "MM-dd"
    $findingsFileName = "Findings$dateForUrl.txt"
    
    # Generate unique 3-digit alphanumeric identifier
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    $uniqueId = -join ((1..3) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    
    # Change to SS directory
    Set-Location -Path $ssPath
    
    # Construct curl command with unique identifier
    $url = "https://filebin.net/PCCHECK$computerName$uniqueId/$findingsFileName"
    
    # Execute curl command using full path to avoid PowerShell alias
    $uploadResult = & "C:\Windows\System32\curl.exe" -X POST $url -H "accept: application/json" -H "Content-Type: application/octet-stream" --data-binary "@$findingsFileName" 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Upload successful! File available at: $url" -ForegroundColor Green
        # Copy URL to clipboard
        Set-Clipboard -Value "https://filebin.net/PCCHECK$computerName$uniqueId"
        Write-Host "URL copied to clipboard!" -ForegroundColor Cyan
    } else {
        Write-Host "Upload failed. Error: $uploadResult" -ForegroundColor Red
        Set-Clipboard -Value "https://filebin.net/PCCHECK$computerName$uniqueId"
        Write-Host "URL copied to clipboard!" -ForegroundColor Cyan
        Write-Host "Please check the bin to see if it failed to upload."
        Write-Host "If the upload failed, please manually upload the file."
    }
} catch {
    Write-Host "Upload failed. Error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "Press any key to exit..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

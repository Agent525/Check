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
            Start-Process PowerShell -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -NoNewWindow
            exit
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
            Start-Process PowerShell -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -NoNewWindow
            exit
        }
        "3" {
            Write-Host "`nStarting Generic Analysis..." -ForegroundColor Green
            break
        }
        "4" {
            Write-Host "`nDelete Previous Filebin" -ForegroundColor Red
            Write-Host "`nPlease use just the bin name, not the full URL." -ForegroundColor Cyan
            Write-Host "`nThe bin name will look like PCCHECK<COMPUTERNAME> and then a unique 3 digit identifier" -ForegroundColor Cyan
            Write-Host ""
            $binName = Read-Host "Enter the bin name to delete"
            
            if ($binName) {
                Write-Host "`nDeleting filebin: $binName..." -ForegroundColor Yellow
                try {
                    $deleteUrl = "https://filebin.net/$binName"
                    
                    # Execute curl command using full path to avoid PowerShell alias
                    $deleteResult = & "C:\Windows\System32\curl.exe" -X DELETE $deleteUrl -H "accept: application/json" 2>&1
                    
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
            Start-Process PowerShell -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -NoNewWindow
            exit
        }
        default {
            Write-Host "Invalid choice. Please enter 1, 2, 3, or 4." -ForegroundColor Red
        }
    }
} while ($choice -notin @("1", "2", "3", "4"))

# Initialize progress tracking
$totalSections = 23  # Updated to include new signature analysis section
$currentSection = 0

# Global array to collect all executable and DLL paths for advanced signature detection
$global:allExecutablePaths = @()

# Function to add paths to global collection
function Add-ExecutablePath {
    param($Path)
    if ($Path -and (Test-Path $Path) -and $Path -match "\.(exe|dll)$") {
        $global:allExecutablePaths += $Path
    }
}

function Update-Progress {
    param($ActivityName)
    $script:currentSection++
    $percentComplete = ($script:currentSection / $totalSections) * 100
    Write-Progress -Activity "General Analysis" -Status $ActivityName -PercentComplete $percentComplete
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

# Comprehensive Kernel DMA Protection Check (includes DMA Protection, Memory Integrity, and Stack Protection)
try {
    $dmaProtectionEnabled = $false
    $memoryIntegrityEnabled = $false
    $kernelStackProtectionEnabled = $false
    $protectionDetails = @()
    
    # Check basic DMA Protection
    try {
        $deviceGuardProps = Get-ComputerInfo | Select-Object -ExpandProperty DeviceGuardAvailableSecurityProperties
        if ($deviceGuardProps -contains "DMA Protection") {
            $dmaProtectionEnabled = $true
            $protectionDetails += "DMA Protection Available"
        }
    } catch {
        $protectionDetails += "DMA Protection Check Failed"
    }
    
    # Check Memory Integrity (HVCI)
    try {
        $hvciStatus = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        if ($hvciStatus) {
            if ($hvciStatus.VirtualizationBasedSecurityStatus -eq 2) {
                $memoryIntegrityEnabled = $true
                $protectionDetails += "Memory Integrity (HVCI) Enabled"
            } else {
                $protectionDetails += "Memory Integrity (HVCI) Disabled"
            }
        } else {
            # Alternative method using registry
            $hvciRegistry = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue
            $hvciHyperV = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
            
            if ($hvciRegistry -and $hvciHyperV -and $hvciRegistry.EnableVirtualizationBasedSecurity -eq 1 -and $hvciHyperV.Enabled -eq 1) {
                $memoryIntegrityEnabled = $true
                $protectionDetails += "Memory Integrity (HVCI) Enabled (Registry)"
            } else {
                $protectionDetails += "Memory Integrity (HVCI) Disabled or Not Available"
            }
        }
    } catch {
        $protectionDetails += "Memory Integrity (HVCI) Check Failed"
    }
    
    # Check Kernel-mode Hardware-enforced Stack Protection
    try {
        $stackProtectionDetails = @()
        
        # Check for Kernel CET (Control Flow Enforcement Technology)
        $cetStatus = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "CetCompatible" -ErrorAction SilentlyContinue
        $stackProtection = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "KernelSEHOPEnabled" -ErrorAction SilentlyContinue
        
        if ($cetStatus -and $cetStatus.CetCompatible -eq 1) {
            $kernelStackProtectionEnabled = $true
            $stackProtectionDetails += "CET Compatible"
        }
        
        if ($stackProtection -and $stackProtection.KernelSEHOPEnabled -eq 1) {
            $kernelStackProtectionEnabled = $true
            $stackProtectionDetails += "SEHOP Enabled"
        }
        
        # Check for additional stack protection features
        $mitigationPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "MitigationAuditOptions" -ErrorAction SilentlyContinue
        if ($mitigationPolicy) {
            $stackProtectionDetails += "Mitigation Audit Options Set"
        }
        
        if ($kernelStackProtectionEnabled) {
            $protectionDetails += "Kernel Stack Protection Enabled ($($stackProtectionDetails -join ', '))"
        } else {
            $protectionDetails += "Kernel Stack Protection Disabled or Not Available"
        }
    } catch {
        $protectionDetails += "Kernel Stack Protection Check Failed"
    }
    
    # Determine overall status - all three must be enabled
    if ($dmaProtectionEnabled -and $memoryIntegrityEnabled -and $kernelStackProtectionEnabled) {
        $overallDmaStatus = "Kernel DMA Protection: Available/Enabled (All Components Active)"
    } else {
        $overallDmaStatus = "Kernel DMA Protection: Not Available/Disabled"
    }
    
    # Add detailed breakdown
    Add-Content -Path $findingsFile -Value $overallDmaStatus
    Add-Content -Path $findingsFile -Value "  Details: $($protectionDetails -join '; ')"
    
} catch {
    Add-Content -Path $findingsFile -Value "Kernel DMA Protection: Unable to determine"
}

# Check Control Flow Guard (CFG) separately
try {
    $cfgEnabled = $false
    $cfgDetails = @()
    
    # Check system-wide CFG policy
    $cfgPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "CfgBitmap" -ErrorAction SilentlyContinue
    if ($cfgPolicy) {
        $cfgEnabled = $true
        $cfgDetails += "System CFG Policy"
    }
    
    # Check if CFG is available in processor
    $processorFeatures = Get-CimInstance Win32_Processor | Select-Object -First 1
    if ($processorFeatures) {
        # CFG support is typically indicated by processor capabilities
        $cfgDetails += "Processor Support Available"
    }
    
    if ($cfgEnabled) {
        $cfgStatus = "Control Flow guard (CFG): Enabled ($($cfgDetails -join ', '))"
    } else {
        $cfgStatus = "Control Flow Guard (CFG): System-level status unclear (Application-specific)"
    }
} catch {
    $cfgStatus = "Control Flow Guard (CFG): Unable to determine"
}
Add-Content -Path $findingsFile -Value $cfgStatus

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

# Function to calculate SHA256 hash
function Get-FileSHA256 {
    param($FilePath)
    try {
        if (Test-Path $FilePath) {
            $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue
            return $hash.Hash
        }
    } catch {
        return $null
    }
    return $null
}

# Function to download and parse cheat database
function Get-CheatDatabase {
    try {
        $databaseUrl = "https://raw.githubusercontent.com/Agent525/Check/refs/heads/main/basicdb.txt"
        $databaseContent = Invoke-WebRequest -Uri $databaseUrl -UseBasicParsing -ErrorAction SilentlyContinue
        
        if ($databaseContent.StatusCode -eq 200) {
            $database = @{}
            $lines = $databaseContent.Content -split "`n"
            
            foreach ($line in $lines) {
                if ($line.Trim() -and $line.Contains(" - ") -and $line.Split(" - ").Count -eq 3) {
                    $parts = $line.Split(" - ")
                    $name = $parts[0].Trim()
                    $sha256 = $parts[1].Trim()
                    $size = $parts[2].Trim()
                    
                    # Create a lookup key using both hash and size
                    $key = "$sha256|$size"
                    $database[$key] = $name
                }
            }
            return $database
        }
    } catch {
        Write-Host "Warning: Unable to download cheat database: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    return @{
    }
}

Update-Progress "Enumerating drive letters..."

# Drive Letters
Add-Section "Drive Letters"
$ntfsDrives = @()
Get-WmiObject Win32_LogicalDisk | ForEach-Object {
    $fileSystem = if ($_.FileSystem) { $_.FileSystem } else { "Unknown" }
    Add-Content -Path $findingsFile -Value "Drive $($_.DeviceID) - $($_.VolumeName) ($($_.DriveType)) - FileSystem: $fileSystem"
    
    # Collect NTFS drives for USN Journal checking
    if ($_.FileSystem -eq "NTFS" -and $_.DriveType -in @(2, 3)) {  # Removable or Fixed drives
        $ntfsDrives += $_.DeviceID.TrimEnd(':')
    }
}

Update-Progress "Checking USN Journal..."

# USN Journal Check
Add-Section "USN Journal"
foreach ($drive in $ntfsDrives) {
    try {
        # Query USN Journal information
        $usnInfo = fsutil usn queryjournal $drive`: 2>&1
        if ($LASTEXITCODE -eq 0) {
            Add-Content -Path $findingsFile -Value "USN Journal for drive $drive`: Present"
        } else {
            Add-Content -Path $findingsFile -Value "USN Journal for drive $drive`: Not Present"
        }
    } catch {
        Add-Content -Path $findingsFile -Value "USN Journal for drive $drive`: Unable to determine"
    }
}

Update-Progress "Checking USN Journal deletion events..."

# USN Journal Deletion Events (Event ID 3079)
Add-Section "USN Journal Deletion Events"
try {
    $usnDeletionEvents = Get-WinEvent -FilterHashtable @{LogName='Application'; ID=3079} -MaxEvents 50 -ErrorAction SilentlyContinue
    if ($usnDeletionEvents) {
        Add-Content -Path $findingsFile -Value "Found USN Journal deletion events:"
        foreach ($event in $usnDeletionEvents) {
            Add-Content -Path $findingsFile -Value "  Time: $($event.TimeCreated) - Message: $($event.Message.Split([Environment]::NewLine)[0])"
        }
    } else {
        Add-Content -Path $findingsFile -Value "No USN Journal deletion events found (Event ID 3079)"
    }
} catch {
    Add-Content -Path $findingsFile -Value "Unable to query USN Journal deletion events: $($_.Exception.Message)"
}

Update-Progress "Checking Windows Defender exclusions..."

# Windows Defender Exclusions
Add-Section "Windows Defender Exclusions"
try {
    $exclusions = Get-MpPreference -ErrorAction SilentlyContinue
    if ($exclusions) {
        # Path Exclusions
        if ($exclusions.ExclusionPath) {
            Add-Content -Path $findingsFile -Value "Path Exclusions:"
            $exclusions.ExclusionPath | ForEach-Object {
                Add-Content -Path $findingsFile -Value "  $_"
            }
        } else {
            Add-Content -Path $findingsFile -Value "Path Exclusions: None"
        }
        
        # Extension Exclusions
        if ($exclusions.ExclusionExtension) {
            Add-Content -Path $findingsFile -Value "Extension Exclusions:"
            $exclusions.ExclusionExtension | ForEach-Object {
                Add-Content -Path $findingsFile -Value "  $_"
            }
        } else {
            Add-Content -Path $findingsFile -Value "Extension Exclusions: None"
        }
        
        # Process Exclusions
        if ($exclusions.ExclusionProcess) {
            Add-Content -Path $findingsFile -Value "Process Exclusions:"
            $exclusions.ExclusionProcess | ForEach-Object {
                Add-Content -Path $findingsFile -Value "  $_"
            }
        } else {
            Add-Content -Path $findingsFile -Value "Process Exclusions: None"
        }
    } else {
        Add-Content -Path $findingsFile -Value "Unable to retrieve Windows Defender exclusions"
    }
} catch {
    Add-Content -Path $findingsFile -Value "Unable to access Windows Defender preferences: $($_.Exception.Message)"
}

Update-Progress "Checking Windows Defender alerts..."

# Windows Defender Alerts
Add-Section "Windows Defender Alerts"
try {
    $defenderEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'} -MaxEvents 100 -ErrorAction SilentlyContinue
    if ($defenderEvents) {
        Add-Content -Path $findingsFile -Value "Recent Windows Defender Events:"
        $defenderEvents | Where-Object { $_.Id -in @(1006, 1007, 1116, 1117) } | ForEach-Object {
            $eventType = switch ($_.Id) {
                1006 { "Malware Detected" }
                1007 { "Action Taken" }
                1116 { "Malware Detected (Real-time)" }
                1117 { "Action Taken (Real-time)" }
                default { "Other Event" }
            }
            Add-Content -Path $findingsFile -Value "  $($_.TimeCreated) - Event ID: $($_.Id) - $eventType"
            if ($_.Message) {
                $messageFirstLine = $_.Message.Split([Environment]::NewLine)[0]
                Add-Content -Path $findingsFile -Value "    Message: $messageFirstLine"
            }
        }
    } else {
        Add-Content -Path $findingsFile -Value "No recent Windows Defender events found"
    }
} catch {
    Add-Content -Path $findingsFile -Value "Unable to query Windows Defender events: $($_.Exception.Message)"
}

Update-Progress "Checking installed antivirus software..."

# Antivirus Detection
Add-Section "Installed Antivirus Software"
$antivirusPaths = @{
    "McAfee" = @("${env:ProgramFiles}\McAfee", "${env:ProgramFiles(x86)}\McAfee", "${env:ProgramFiles}\Common Files\McAfee")
    "Malwarebytes" = @("${env:ProgramFiles}\Malwarebytes", "${env:ProgramFiles(x86)}\Malwarebytes")
    "Bitdefender" = @("${env:ProgramFiles}\Bitdefender", "${env:ProgramFiles(x86)}\Bitdefender")
    "Kaspersky" = @("${env:ProgramFiles}\Kaspersky Lab", "${env:ProgramFiles(x86)}\Kaspersky Lab", "${env:ProgramFiles}\Kaspersky Security Cloud")
    "Norton" = @("${env:ProgramFiles}\Norton", "${env:ProgramFiles(x86)}\Norton", "${env:ProgramFiles}\NortonLifeLock")
    "Avast" = @("${env:ProgramFiles}\AVAST Software", "${env:ProgramFiles(x86)}\AVAST Software")
    "AVG" = @("${env:ProgramFiles}\AVG", "${env:ProgramFiles(x86)}\AVG")
    "TotalAV" = @("${env:ProgramFiles}\TotalAV", "${env:ProgramFiles(x86)}\TotalAV")
}

$foundAntivirus = @()
foreach ($antivirus in $antivirusPaths.Keys) {
    foreach ($path in $antivirusPaths[$antivirus]) {
        if (Test-Path $path) {
            $foundAntivirus += "$antivirus found at: $path"
            break
        }
    }
}

if ($foundAntivirus.Count -gt 0) {
    $foundAntivirus | ForEach-Object {
        Add-Content -Path $findingsFile -Value $_
    }
} else {
    Add-Content -Path $findingsFile -Value "No common antivirus software detected"
}

Update-Progress "Enumerating USB devices..."

# USB Devices
Add-Section "USB Devices"
try {
    Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 } | ForEach-Object {
        Add-Content -Path $findingsFile -Value "USB Drive: $($_.DeviceID) - $($_.VolumeName)"
    }
    
    Get-WmiObject Win32_USBHub | ForEach-Object {
        $deviceId = $_.DeviceID
        if ($deviceId -match "USB\\VID_([0-9A-F]{4})&PID_([0-9A-F]{4})") {
            $vendorId = $matches[1]
            $productId = $matches[2]
            Add-Content -Path $findingsFile -Value "USB Hub: $($_.Name) - USB - Vendor ID: $vendorId Device ID: $productId"
        } else {
            Add-Content -Path $findingsFile -Value "USB Hub: $($_.Name) - $deviceId"
        }
    }
} catch {
    Add-Content -Path $findingsFile -Value "Unable to enumerate USB devices"
}

# PCIE Devices
Add-Section "PCIE Devices"
try {
    Get-WmiObject Win32_PnPEntity | Where-Object { $_.DeviceID -match "PCI\\" } | ForEach-Object {
        $deviceId = $_.DeviceID
        if ($deviceId -match "PCI\\VEN_([0-9A-F]{4})&DEV_([0-9A-F]{4})") {
            $vendorId = $matches[1]
            $deviceIdNum = $matches[2]
            Add-Content -Path $findingsFile -Value "PCIE Device: $($_.Name) - PCI - Vendor ID: $vendorId Device ID: $deviceIdNum"
        } else {
            Add-Content -Path $findingsFile -Value "PCIE Device: $($_.Name) - $deviceId"
        }
    }
} catch {
    Add-Content -Path $findingsFile -Value "Unable to enumerate PCIE devices"
}

Update-Progress "Checking Windows services status..."

# Windows Services Status
Add-Section "Windows Services Status"
$servicesToCheck = @("DPS", "PcaSvc", "AppInfo", "EventLog", "BAM", "SysMain")
foreach ($serviceName in $servicesToCheck) {
    try {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            Add-Content -Path $findingsFile -Value "$serviceName : $($service.Status)"
        } else {
            Add-Content -Path $findingsFile -Value "$serviceName : Service not found"
        }
    } catch {
        Add-Content -Path $findingsFile -Value "$serviceName : Unable to determine status"
    }
}

Update-Progress "Detecting installed browsers..."

# Browser Detection
Add-Section "Installed Browsers"
$browserPaths = @{
    "Chrome" = @("${env:ProgramFiles}\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe")
    "Firefox" = @("${env:ProgramFiles}\Mozilla Firefox\firefox.exe", "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe")
    "Edge" = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe")
    "Opera" = @("${env:ProgramFiles}\Opera\opera.exe", "${env:ProgramFiles(x86)}\Opera\opera.exe")
    "Opera GX" = @("${env:ProgramFiles}\Opera GX\opera.exe", "${env:ProgramFiles(x86)}\Opera GX\opera.exe")
    "Brave" = @("${env:ProgramFiles}\BraveSoftware\Brave-Browser\Application\brave.exe", "${env:ProgramFiles(x86)}\BraveSoftware\Brave-Browser\Application\brave.exe")
}

foreach ($browser in $browserPaths.Keys) {
    foreach ($path in $browserPaths[$browser]) {
        if (Test-Path $path) {
            Add-Content -Path $findingsFile -Value "$browser found at: $path"
        }
    }
}

Update-Progress "Scanning USB drives..."

# USB Drives Scan
Add-Section "USB Drives Scan"
try {
    # Download cheat database
    Write-Host "Downloading cheat database for signature checking..." -ForegroundColor Cyan
    $cheatDatabase = Get-CheatDatabase
    
    # Get all USB drives
    $usbDrives = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 }
    
    if ($usbDrives) {
        foreach ($usbDrive in $usbDrives) {
            $driveLetter = $usbDrive.DeviceID
            Add-Content -Path $findingsFile -Value "Scanning USB Drive: $driveLetter - $($usbDrive.VolumeName)"
            
            if (Test-Path $driveLetter) {
                $usbResults = @{
                    detectedCheats = @()
                    exe = @()
                    dll = @()
                    zip = @()
                    rar = @()
                }
                
                try {
                    Get-ChildItem $driveLetter -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match "\.(zip|rar|exe|dll)$" } | ForEach-Object {
                        if ($_.Extension -eq ".exe") {
                            # Add to global paths collection
                            Add-ExecutablePath $_.FullName
                            
                            # Calculate hash and get file size for executables
                            $fileHash = Get-FileSHA256 $_.FullName
                            $fileSize = $_.Length
                            $lookupKey = "$fileHash|$fileSize"
                            
                            # Check against cheat database
                            if ($cheatDatabase.ContainsKey($lookupKey)) {
                                $cheatName = $cheatDatabase[$lookupKey]
                                $usbResults.detectedCheats += "$($_.FullName) (*$cheatName* Detected)"
                            } elseif (-not (Test-FileSignature $_.FullName)) {
                                $usbResults.exe += $_.FullName
                            }
                        } elseif ($_.Extension -eq ".dll") {
                            # Add to global paths collection
                            Add-ExecutablePath $_.FullName
                            
                            if (-not (Test-FileSignature $_.FullName)) {
                                $usbResults.dll += $_.FullName
                            }
                        } elseif ($_.Extension -eq ".zip") {
                            $usbResults.zip += $_.FullName
                        } elseif ($_.Extension -eq ".rar") {
                            $usbResults.rar += $_.FullName
                        }
                    }
                    
                    # Output detected cheats first
                    $usbResults.detectedCheats | Sort-Object { $_.Length } | ForEach-Object { Add-Content -Path $findingsFile -Value "  $_" }
                    
                    # Then output other unsigned executables
                    $usbResults.exe | Sort-Object { $_.Length } | ForEach-Object { Add-Content -Path $findingsFile -Value "  $_" }
                    
                    # Then unsigned DLLs
                    $usbResults.dll | Sort-Object { $_.Length } | ForEach-Object { Add-Content -Path $findingsFile -Value "  $_" }
                    
                    # Finally output archives
                    $usbResults.rar | Sort-Object { $_.Length } | ForEach-Object { Add-Content -Path $findingsFile -Value "  $_" }
                    $usbResults.zip | Sort-Object { $_.Length } | ForEach-Object { Add-Content -Path $findingsFile -Value "  $_" }
                    
                } catch {
                    Add-Content -Path $findingsFile -Value "  Unable to scan drive contents: $($_.Exception.Message)"
                }
            } else {
                Add-Content -Path $findingsFile -Value "  Drive not accessible"
            }
        }
    } else {
        Add-Content -Path $findingsFile -Value "No USB drives detected"
    }
} catch {
    Add-Content -Path $findingsFile -Value "Unable to enumerate USB drives for scanning"
}

Update-Progress "Scanning Downloads folder..."

# Downloads Check
Add-Section "Downloads"
try {
    $downloadsPath = [Environment]::GetFolderPath("UserProfile") + "\Downloads"
    if (Test-Path $downloadsPath) {
        # Use existing cheat database if already downloaded, otherwise download it
        if (-not $cheatDatabase) {
            Write-Host "Downloading cheat database for signature checking..." -ForegroundColor Cyan
            $cheatDatabase = Get-CheatDatabase
        }
        
        $downloadResults = @{
            detectedCheats = @()
            exe = @()
            zip = @()
            rar = @()
        }
        
        Get-ChildItem $downloadsPath -Recurse | Where-Object { $_.Extension -match "\.(zip|rar|exe)$" } | ForEach-Object {
            if ($_.Extension -eq ".exe") {
                # Add to global paths collection
                Add-ExecutablePath $_.FullName
                
                # Calculate hash and get file size for all executables
                $fileHash = Get-FileSHA256 $_.FullName
                $fileSize = $_.Length
                $lookupKey = "$fileHash|$fileSize"
                
                # Check against cheat database
                if ($cheatDatabase.ContainsKey($lookupKey)) {
                    $cheatName = $cheatDatabase[$lookupKey]
                    $downloadResults.detectedCheats += "$($_.FullName) (*$cheatName* Detected)"
                } elseif (-not (Test-FileSignature $_.FullName)) {
                    $downloadResults.exe += $_.FullName
                }
            } elseif ($_.Extension -eq ".zip") {
                $downloadResults.zip += $_.FullName
            } elseif ($_.Extension -eq ".rar") {
                $downloadResults.rar += $_.FullName
            }
        }
        
        # Output detected cheats first
        $downloadResults.detectedCheats | Sort-Object { $_.Length } | ForEach-Object { Add-Content -Path $findingsFile -Value $_ }
        
        # Then output other unsigned executables
        $downloadResults.exe | Sort-Object { $_.Length } | ForEach-Object { Add-Content -Path $findingsFile -Value $_ }
        
        # Finally output archives
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
        $hashTable = @{
        }
        $suspiciousFiles = @{
        }
        
        # Get all prefetch files
        $files = Get-ChildItem $prefetchPath -Filter "*.pf"
        
        # Perform advanced analysis on each prefetch file
        foreach ($file in $files) {
            try {
                # Check if file is read-only (suspicious)
                if ($file.IsReadOnly) {
                    if (-not $suspiciousFiles.ContainsKey($file.Name)) {
                        $suspiciousFiles[$file.Name] = "$($file.Name) is read-only"
                    }
                }
                
                # Validate prefetch file header
                $reader = [System.IO.StreamReader]::new($file.FullName)
                $buffer = New-Object char[] 3
                $null = $reader.ReadBlock($buffer, 0, 3)
                $reader.Close()
                
                $firstThreeChars = -join $buffer
                
                if ($firstThreeChars -ne "MAM") {
                    if (-not $suspiciousFiles.ContainsKey($file.Name)) {
                        $suspiciousFiles[$file.Name] = "$($file.Name) is not a valid prefetch file"
                    }
                }
                
                # Calculate hash for duplicate detection
                $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256
                
                if ($hashTable.ContainsKey($hash.Hash)) {
                    $hashTable[$hash.Hash].Add($file.Name)
                } else {
                    $hashTable[$hash.Hash] = [System.Collections.Generic.List[string]]::new()
                    $hashTable[$hash.Hash].Add($file.Name)
                }
                
                # Add to results for normal display
                $prefetchResults += [PSCustomObject]@{
                    Name = $file.Name
                    LastWriteTime = $file.LastWriteTime
                    DisplayText = "$($file.Name) - $($file.LastWriteTime)"
                }
                
            } catch {
                Add-Content -Path $findingsFile -Value "Error analyzing file $($file.FullName): $($_.Exception.Message)"
            }
        }
        
        # Check for duplicate hashes (indicating modified prefetch files)
        $repeatedHashes = $hashTable.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }
        
        if ($repeatedHashes) {
            foreach ($entry in $repeatedHashes) {
                foreach ($file in $entry.Value) {
                    if (-not $suspiciousFiles.ContainsKey($file)) {
                        $suspiciousFiles[$file] = "$file was modified with type or echo"
                    }
                }
            }
        }
        
        # Output suspicious files first
        if ($suspiciousFiles.Count -gt 0) {
            Add-Content -Path $findingsFile -Value "Suspicious Prefetch Files:"
            foreach ($key in $suspiciousFiles.Keys) {
                Add-Content -Path $findingsFile -Value "  $key : $($suspiciousFiles[$key])"
            }
            Add-Content -Path $findingsFile -Value ""
        }
        
        # Output all prefetch files sorted by time
        Add-Content -Path $findingsFile -Value "All Prefetch Files (chronological order):"
        $prefetchResults | Sort-Object LastWriteTime | ForEach-Object {
            Add-Content -Path $findingsFile -Value $_.DisplayText
        }
        
        # Summary statistics
        Add-Content -Path $findingsFile -Value ""
        Add-Content -Path $findingsFile -Value "Prefetch Analysis Summary:"
        Add-Content -Path $findingsFile -Value "  Total prefetch files: $($files.Count)"
        Add-Content -Path $findingsFile -Value "  Suspicious files detected: $($suspiciousFiles.Count)"
        Add-Content -Path $findingsFile -Value "  Duplicate hash groups: $($repeatedHashes.Count)"
        
        if ($suspiciousFiles.Count -eq 0) {
            Add-Content -Path $findingsFile -Value "  Prefetch folder appears clean"
        }
        
    } else {
        Add-Content -Path $findingsFile -Value "Prefetch folder not found or inaccessible"
    }
} catch {
    Add-Content -Path $findingsFile -Value "Unable to access Prefetch folder: $($_.Exception.Message)"
}

Update-Progress "Checking Recent files..."

# Last Ran Files using NirSoft LastActivityView
Add-Section "Last Ran Files"
try {
    # Download NirSoft LastActivityView tool
    Write-Host "Downloading Last Activity View tool..." -ForegroundColor Cyan
    
    $lastActivityToolPath = Join-Path $ssPath "LastActivityView.exe"
    Invoke-WebRequest -Uri "https://github.com/Agent525/Check/raw/main/LastActivityView.exe" -OutFile $lastActivityToolPath -ErrorAction SilentlyContinue
    
    if (Test-Path $lastActivityToolPath) {
        # Extract last activity data
        $lastActivityCSV = Join-Path $ssPath "last_activity.csv"
        
        # Remove existing CSV if it exists
        if (Test-Path $lastActivityCSV) {
            Remove-Item $lastActivityCSV -Force -ErrorAction SilentlyContinue
        }
        
        Write-Host "Extracting last activity data..." -ForegroundColor Cyan
        & $lastActivityToolPath /scomma $lastActivityCSV /sort "~Date/Time"
        
        # Wait for CSV file to be created and populated (up to 30 seconds)
        $timeout = 30
        $elapsed = 0
        do {
            Start-Sleep -Seconds 1
            $elapsed++
            if (Test-Path $lastActivityCSV) {
                # Check if file has content (more than just headers)
                try {
                    $content = Get-Content $lastActivityCSV -ErrorAction SilentlyContinue
                    if ($content -and $content.Count -gt 1) {
                        break
                    }
                } catch {
                    # Continue waiting
                }
            }
        } while ($elapsed -lt $timeout)
        
        if (Test-Path $lastActivityCSV) {
            try {
                # Use existing cheat database if already downloaded
                if (-not $cheatDatabase) {
                    Write-Host "Downloading cheat database for signature checking..." -ForegroundColor Cyan
                    $cheatDatabase = Get-CheatDatabase
                }
                
                $lastActivityData = Import-Csv $lastActivityCSV -ErrorAction SilentlyContinue
                
                if ($lastActivityData -and $lastActivityData.Count -gt 0) {
                    $lastActivityResults = @{
                        detectedCheats = @()
                        exe = @()
                    }
                    
                    foreach ($entry in $lastActivityData) {
                        # Get all possible field names for different columns
                        $actionType = if ($entry.'Action Type') { $entry.'Action Type' } elseif ($entry.'Type') { $entry.'Type' } else { "" }
                        $filename = if ($entry.'Filename') { $entry.'Filename' } elseif ($entry.'File') { $entry.'File' } elseif ($entry.'Path') { $entry.'Path' } else { "" }
                        $description = if ($entry.'Description') { $entry.'Description' } elseif ($entry.'Details') { $entry.'Details' } else { "" }
                        $timestamp = if ($entry.'Date/Time') { $entry.'Date/Time' } elseif ($entry.'Time') { $entry.'Time' } elseif ($entry.'DateTime') { $entry.'DateTime' } else { "Unknown" }
                        
                        # Look for executable paths in multiple fields
                        $executablePaths = @()
                        
                        # Check filename field
                        if ($filename -and $filename.ToLower().EndsWith(".exe")) {
                            $executablePaths += $filename
                        }
                        
                        # Check description for paths
                        if ($description) {
                            # Look for various executable path patterns
                            $pathPatterns = @(
                                '([A-Z]:\\[^"<>|*?\r\n]+\.exe)',  # Standard Windows path
                                '"([^"]+\.exe)"',                 # Quoted paths
                                '([^\s]+\.exe)',                  # Simple exe paths
                                'File:\s*([^\s,]+\.exe)',         # File: prefix
                                'Path:\s*([^\s,]+\.exe)'          # Path: prefix
                            )
                            
                            foreach ($pattern in $pathPatterns) {
                                if ($description -match $pattern) {
                                    $extractedPath = $matches[1]
                                    if ($extractedPath -and $extractedPath.ToLower().EndsWith(".exe")) {
                                        $executablePaths += $extractedPath
                                    }
                                }
                            }
                        }
                        
                        # Process all found executable paths
                        foreach ($exePath in $executablePaths) {
                            # Clean up the path
                            $exePath = $exePath.Trim('"').Trim()
                            
                            # Skip if path is too short or invalid
                            if ($exePath.Length -lt 5 -or -not $exePath.ToLower().EndsWith(".exe")) {
                                continue
                            }
                            
                            # Check if file still exists for hash calculation
                            if (Test-Path $exePath) {
                                try {
                                    # Add to global paths collection
                                    Add-ExecutablePath $exePath
                                    
                                    $fileHash = Get-FileSHA256 $exePath
                                    $fileSize = (Get-Item $exePath -ErrorAction SilentlyContinue).Length
                                    
                                    if ($fileHash -and $fileSize) {
                                        $lookupKey = "$fileHash|$fileSize"
                                        
                                        # Check against cheat database
                                        if ($cheatDatabase.ContainsKey($lookupKey)) {
                                            $cheatName = $cheatDatabase[$lookupKey]
                                            $lastActivityResults.detectedCheats += "$exePath (*$cheatName* Detected) - Last Activity: $timestamp"
                                        } elseif (-not (Test-FileSignature $exePath)) {
                                            $lastActivityResults.exe += "$exePath - Last Activity: $timestamp"
                                        }
                                    } else {
                                        # Couldn't get hash/size but file exists
                                        $lastActivityResults.exe += "$exePath - Last Activity: $timestamp"
                                    }
                                } catch {
                                    # Error processing file
                                    $lastActivityResults.exe += "$exePath (Processing Error) - Last Activity: $timestamp"
                                }
                            } else {
                                # File doesn't exist anymore, but still record the activity
                                $lastActivityResults.exe += "$exePath (File Not Found) - Last Activity: $timestamp"
                            }
                        }
                    }
                    
                    # Remove duplicates and sort
                    $lastActivityResults.detectedCheats = $lastActivityResults.detectedCheats | Sort-Object -Unique
                    $lastActivityResults.exe = $lastActivityResults.exe | Sort-Object -Unique
                    
                    # Output detected cheats first
                    $lastActivityResults.detectedCheats | Select-Object -First 100 | ForEach-Object {
                        Add-Content -Path $findingsFile -Value $_
                    }
                    
                    # Then output other executables
                    $lastActivityResults.exe | Select-Object -First 100 | ForEach-Object {
                        Add-Content -Path $findingsFile -Value $_
                    }
                    
                    if ($lastActivityResults.detectedCheats.Count -eq 0 -and $lastActivityResults.exe.Count -eq 0) {
                        Add-Content -Path $findingsFile -Value "No recent executable activity found"
                    }
                } else {
                    Add-Content -Path $findingsFile -Value "No last activity data found"
                }
            } catch {
                Add-Content -Path $findingsFile -Value "Unable to parse last activity data: $($_.Exception.Message)"
            }
        } else {
            Add-Content -Path $findingsFile -Value "Last activity extraction timed out or failed"
        }
    } else {
        Add-Content -Path $findingsFile -Value "Unable to download LastActivityView tool"
    }
} catch {
    Add-Content -Path $findingsFile -Value "Unable to analyze last activity data: $($_.Exception.Message)"
} finally {
    # Comprehensive cleanup for LastActivityView
    $lastActivityCleanupFiles = @(
        (Join-Path $ssPath "last_activity.csv"),
        (Join-Path $ssPath "LastActivityView.exe")
    )
    
    foreach ($file in $lastActivityCleanupFiles) {
        if (Test-Path $file) {
            try {
                Remove-Item $file -Force -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 100  # Brief pause to ensure deletion
            } catch {
                # Try alternative cleanup method
                try {
                    [System.IO.File]::Delete($file)
                } catch {
                    # Silent fail - file will be cleaned up later
                }
            }
        }
    }
}

# Recent Files (shell:recent)
Add-Section "Recent Files"
try {
    $recentPath = [Environment]::GetFolderPath("Recent")
    if (Test-Path $recentPath) {
        # Use existing cheat database if already downloaded
        if (-not $cheatDatabase) {
            Write-Host "Downloading cheat database for signature checking..." -ForegroundColor Cyan
            $cheatDatabase = Get-CheatDatabase
        }
        
        $recentResults = @{
            detectedCheats = @()
            exe = @()
            dll = @()
            zip = @()
            rar = @()
        }
        
        # Get all .lnk files in Recent folder and resolve their targets
        Get-ChildItem $recentPath -Filter "*.lnk" -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                # Create WScript.Shell object to resolve shortcut
                $shell = New-Object -ComObject WScript.Shell
                $shortcut = $shell.CreateShortcut($_.FullName)
                $targetPath = $shortcut.TargetPath
                
                # Check if target exists and has the extensions we're looking for
                if ($targetPath -and (Test-Path $targetPath) -and $targetPath -match "\.(exe|dll|zip|rar)$") {
                    $targetFile = Get-Item $targetPath -ErrorAction SilentlyContinue
                    if ($targetFile) {
                        $extension = $targetFile.Extension.ToLower()
                        
                        if ($extension -eq ".exe") {
                            # Add to global paths collection
                            Add-ExecutablePath $targetFile.FullName
                            
                            # Calculate hash and get file size for executables
                            $fileHash = Get-FileSHA256 $targetFile.FullName
                            $fileSize = $targetFile.Length
                            $lookupKey = "$fileHash|$fileSize"
                            
                            # Check against cheat database
                            if ($cheatDatabase.ContainsKey($lookupKey)) {
                                $cheatName = $cheatDatabase[$lookupKey]
                                $recentResults.detectedCheats += "$($targetFile.FullName) (*$cheatName* Detected)"
                            } elseif (-not (Test-FileSignature $targetFile.FullName)) {
                                $recentResults.exe += $targetFile.FullName
                            }
                        } elseif ($extension -eq ".dll") {
                            # Add to global paths collection
                            Add-ExecutablePath $targetFile.FullName
                            
                            if (-not (Test-FileSignature $targetFile.FullName)) {
                                $recentResults.dll += $targetFile.FullName
                            }
                        } elseif ($extension -eq ".zip") {
                            $recentResults.zip += $targetFile.FullName
                        } elseif ($extension -eq ".rar") {
                            $recentResults.rar += $targetFile.FullName
                        }
                    }
                }
            } catch {
                # Skip files that can't be processed
            } finally {
                # Clean up COM object
                if ($shell) {
                    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null
                }
            }
        }
        
        # Output detected cheats first
        $recentResults.detectedCheats | Sort-Object { $_.Length } | ForEach-Object { Add-Content -Path $findingsFile -Value $_ }
        
        # Then output other unsigned executables
        $recentResults.exe | Sort-Object { $_.Length } | ForEach-Object { Add-Content -Path $findingsFile -Value $_ }
        
        # Then unsigned DLLs
        $recentResults.dll | Sort-Object { $_.Length } | ForEach-Object { Add-Content -Path $findingsFile -Value $_ }
        
        # Finally output archives
        $recentResults.rar | Sort-Object { $_.Length } | ForEach-Object { Add-Content -Path $findingsFile -Value $_ }
        $recentResults.zip | Sort-Object { $_.Length } | ForEach-Object { Add-Content -Path $findingsFile -Value $_ }
        
    } else {
        Add-Content -Path $findingsFile -Value "Unable to access Recent folder"
    }
} catch {
    Add-Content -Path $findingsFile -Value "Unable to access Recent folder: $($_.Exception.Message)"
}

Update-Progress "Checking browser history and downloads..."

# Browser History and Downloads using NirSoft tools
Add-Section "Browser History and Downloads"
try {
    # Define suspicious keywords and domains to filter for
    $suspiciousKeywords = @(
        "cheat", "cheats", "loader", "injector", "sellix", "r6s", "fivem", 
        "autoclicker", "macro", "no recoil", "norecoil", "aimbot", "wallhacks", "bypass", "cdn.discordapp.com",
        "myloader.cc", "perc.gg", "ssz.gg", "time2win.net", "qlmshop.com", "420-services.net",
        "eulencheats.com", "lmarket.net", "battlelog.co", "cheatarmy.com", "cosmocheats.com",
        "ring-1.io", "skript.gg", "tzproject.com", "hxcheats.tech", "skycheats.com",
        "wh-satano.ru", "susano.re", "vape.gg", "neverlack.in", "liquidbounce.net", 
        "gtav", "xeno", "project", "d3d10", "free", "r6", "macro", "script", "dumper", "exploit",
        "hack", "hacks", "loader", "inject", "injector", "crack", "bypass", "cheatengine", "cheat engine"
    )
    $suspiciousDomains = @(".gg", ".cc", ".io", ".wtf", ".ru", ".xyz")
    
    # Define URLs to exclude
    $excludeKeywords = @(
        "googleadservices", "googlesyndication", "googletagmanager", "doubleclick",
        "chrome-extension://", "moz-extension://", "extension://", "chrome://", "about:",
        "edge://", "opera://", "brave://", "firefox://", "data:", "blob:",
        "accounts.google.com", "awstrack.me"
    )
    
    # Function to check if URL contains suspicious content
    function Test-SuspiciousUrl {
        param($Url)
        if (-not $Url) { return $false }
        
        $urlLower = $Url.ToLower()
        
        # First check if URL should be excluded
        foreach ($exclude in $excludeKeywords) {
            if ($urlLower.Contains($exclude)) {
                return $false
            }
        }
        
        # Check for suspicious keywords
        foreach ($keyword in $suspiciousKeywords) {
            if ($urlLower.Contains($keyword)) {
                return $true
            }
        }
        
        # Check for suspicious domains
        foreach ($domain in $suspiciousDomains) {
            if ($urlLower.Contains($domain)) {
                return $true
            }
        }
        
        return $false
    }
    
    # Download NirSoft tools
    Write-Host "Downloading browser analysis tools..." -ForegroundColor Cyan
    
    try {
        $historyToolPath = Join-Path $ssPath "BrowsingHistoryView.exe"
        $downloadsToolPath = Join-Path $ssPath "BrowserDownloadsView.exe"
        
        Invoke-WebRequest -Uri "https://github.com/Agent525/Check/raw/main/BrowsingHistoryView.exe" -OutFile $historyToolPath -ErrorAction SilentlyContinue
        Invoke-WebRequest -Uri "https://github.com/Agent525/Check/raw/main/BrowserDownloadsView.exe" -OutFile $downloadsToolPath -ErrorAction SilentlyContinue
        
        if (Test-Path $historyToolPath) {
            # Extract browser history
            $historyCSV = Join-Path $ssPath "browser_history.csv"
            
            # Remove existing CSV if it exists
            if (Test-Path $historyCSV) {
                Remove-Item $historyCSV -Force -ErrorAction SilentlyContinue
            }
            
            Write-Host "Extracting browser history..." -ForegroundColor Cyan
            & $historyToolPath /scomma $historyCSV /LoadIE 1 /LoadFirefox 1 /LoadChrome 1 /LoadSafari 1 /VisitTimeFilterType 3 /VisitTimeFilterValue 30
            
            # Wait for CSV file to be created and populated (up to 30 seconds)
            $timeout = 30
            $elapsed = 0
            do {
                Start-Sleep -Seconds 1
                $elapsed++
                if (Test-Path $historyCSV) {
                    # Check if file has content (more than just headers)
                    try {
                        $content = Get-Content $historyCSV -ErrorAction SilentlyContinue
                        if ($content -and $content.Count -gt 1) {
                            break
                        }
                    } catch {
                        # Continue waiting
                    }
                }
            } while ($elapsed -lt $timeout)
            
            if (Test-Path $historyCSV) {
                Add-Content -Path $findingsFile -Value "Suspicious Browser History (Last 30 days):"
                try {
                    $historyData = Import-Csv $historyCSV -ErrorAction SilentlyContinue
                    
                    if ($historyData -and $historyData.Count -gt 0) {
                        $suspiciousHistory = @()
                        foreach ($entry in $historyData) {
                            if (Test-SuspiciousUrl $entry.URL) {
                                $suspiciousHistory += "$($entry.'Web Browser'): $($entry.URL) - Visited: $($entry.'Visit Time')"
                            }
                        }
                        
                        if ($suspiciousHistory.Count -gt 0) {
                            $suspiciousHistory | Select-Object -First 50 | ForEach-Object {
                                Add-Content -Path $findingsFile -Value "  $_"
                            }
                        } else {
                            Add-Content -Path $findingsFile -Value "  No suspicious browser history found"
                        }
                    } else {
                        Add-Content -Path $findingsFile -Value "  No browser history data found"
                    }
                } catch {
                    Add-Content -Path $findingsFile -Value "  Unable to parse browser history data: $($_.Exception.Message)"
                }
                
                # Clean up history CSV
                Remove-Item $historyCSV -ErrorAction SilentlyContinue
            } else {
                Add-Content -Path $findingsFile -Value "  Browser history extraction timed out or failed"
            }
        }
        
        if (Test-Path $downloadsToolPath) {
            # Extract browser downloads
            $downloadsCSV = Join-Path $ssPath "browser_downloads.csv"
            
            # Remove existing CSV if it exists
            if (Test-Path $downloadsCSV) {
                Remove-Item $downloadsCSV -Force -ErrorAction SilentlyContinue
            }
            
            Write-Host "Extracting browser downloads..." -ForegroundColor Cyan
            & $downloadsToolPath /scomma $downloadsCSV /DownloadTimeFilterType 6 /DownloadTimeFilterValue 30
            
            # Wait for CSV file to be created and populated (up to 30 seconds)
            $timeout = 30
            $elapsed = 0
            do {
                Start-Sleep -Seconds 1
                $elapsed++
                if (Test-Path $downloadsCSV) {
                    # Check if file has content (more than just headers)
                    try {
                        $content = Get-Content $downloadsCSV -ErrorAction SilentlyContinue
                        if ($content -and $content.Count -gt 1) {
                            break
                        }
                    } catch {
                        # Continue waiting
                    }
                }
            } while ($elapsed -lt $timeout)
            
            if (Test-Path $downloadsCSV) {
                Add-Content -Path $findingsFile -Value ""
                Add-Content -Path $findingsFile -Value "Suspicious Browser Downloads (Last 30 days):"
                try {
                    $downloadsData = Import-Csv $downloadsCSV -ErrorAction SilentlyContinue
                    
                    if ($downloadsData -and $downloadsData.Count -gt 0) {
                        $suspiciousDownloads = @()
                        foreach ($entry in $downloadsData) {
                            $downloadUrl = if ($entry.'Download URL 1') { $entry.'Download URL 1' } else { $entry.'Download URL' }
                            $webPageUrl = if ($entry.'Web Page URL') { $entry.'Web Page URL' } else { "" }
                            $filename = if ($entry.'Full Path Filename') { $entry.'Full Path Filename' } else { $entry.'Filename' }
                            
                            # Check download URL, web page URL, and filename for suspicious content
                            if ((Test-SuspiciousUrl $downloadUrl) -or (Test-SuspiciousUrl $webPageUrl) -or 
                                ($filename -and ($filename.ToLower() -match "(cheat|hack|loader|injector|aimbot|wallhack|macro|autoclicker|bypass)"))) {
                                
                                # Clean up Discord CDN filenames - remove everything after file extension
                                $cleanFilename = $filename
                                if ($downloadUrl -and $downloadUrl.ToLower().Contains("cdn.discordapp.com")) {
                                    # Extract just the filename with extension, remove query parameters and extra data
                                    if ($filename -match '([^\\\/]+\.[a-zA-Z0-9]+)') {
                                        $cleanFilename = $matches[1]
                                    }
                                }
                                
                                $downloadInfo = "$($entry.'Web Browser'): $cleanFilename"
                                if ($downloadUrl) { $downloadInfo += " - URL: $downloadUrl" }
                                if ($entry.'Start Time') { $downloadInfo += " - Downloaded: $($entry.'Start Time')" }
                                
                                $suspiciousDownloads += $downloadInfo
                            }
                        }
                        
                        if ($suspiciousDownloads.Count -gt 0) {
                            $suspiciousDownloads | Select-Object -First 50 | ForEach-Object {
                                Add-Content -Path $findingsFile -Value "  $_"
                            }
                        } else {
                            Add-Content -Path $findingsFile -Value "  No suspicious browser downloads found"
                        }
                    } else {
                        Add-Content -Path $findingsFile -Value "  No browser downloads data found"
                    }
                } catch {
                    Add-Content -Path $findingsFile -Value "  Unable to parse browser downloads data: $($_.Exception.Message)"
                }
                
                # Clean up downloads CSV
                Remove-Item $downloadsCSV -ErrorAction SilentlyContinue
            } else {
                Add-Content -Path $findingsFile -Value "  Browser downloads extraction timed out or failed"
            }
        }
        
        # Clean up NirSoft tools and files with enhanced deletion
        try {
            # Force stop any running processes first
            Get-Process | Where-Object { $_.ProcessName -match "BrowsingHistoryView|BrowserDownloadsView" } | Stop-Process -Force -ErrorAction SilentlyContinue
            
            # Wait a moment for processes to fully terminate
            Start-Sleep -Seconds 2
            
            # Enhanced cleanup with multiple attempts
            $browserCleanupFiles = @(
                (Join-Path $ssPath "browser_history.csv"),
                (Join-Path $ssPath "browser_downloads.csv"),
                (Join-Path $ssPath "BrowsingHistoryView.exe"),
                (Join-Path $ssPath "BrowserDownloadsView.exe")
            )
            
            foreach ($tempFile in $browserCleanupFiles) {
                if (Test-Path $tempFile) {
                    $attempts = 0
                    $maxAttempts = 3
                    
                    while ($attempts -lt $maxAttempts -and (Test-Path $tempFile)) {
                        try {
                            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                            Start-Sleep -Milliseconds 200
                        } catch {
                            # Try alternative deletion method
                            try {
                                [System.IO.File]::Delete($tempFile)
                            } catch {
                                # If still failing, try to move and delete
                                try {
                                    $tempName = $tempFile + ".tmp" + (Get-Random)
                                    Move-Item $tempFile $tempName -Force -ErrorAction SilentlyContinue
                                    Remove-Item $tempName -Force -ErrorAction SilentlyContinue
                                } catch {
                                    # Final attempt with .NET method
                                    try {
                                        [System.GC]::Collect()
                                        [System.GC]::WaitForPendingFinalizers()
                                        [System.IO.File]::Delete($tempFile)
                                    } catch {
                                        # Silent fail - will be cleaned up on next run
                                    }
                                }
                            }
                        }
                        $attempts++
                        if ($attempts -lt $maxAttempts) {
                            Start-Sleep -Milliseconds 500
                        }
                    }
                }
            }
        } catch {
            # Silent cleanup failure - files may persist but won't affect functionality
        }
        
    } catch {
        Add-Content -Path $findingsFile -Value "Unable to download or execute browser analysis tools: $($_.Exception.Message)"
        
        # Enhanced cleanup on error as well
        try {
            Get-Process | Where-Object { $_.ProcessName -match "BrowsingHistoryView|BrowserDownloadsView" } | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
            
            $browserCleanupFiles = @(
                (Join-Path $ssPath "browser_history.csv"),
                (Join-Path $ssPath "browser_downloads.csv"),
                (Join-Path $ssPath "BrowsingHistoryView.exe"),
                (Join-Path $ssPath "BrowserDownloadsView.exe")
            )
            
            foreach ($tempFile in $browserCleanupFiles) {
                if (Test-Path $tempFile) {
                    try {
                        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                        [System.IO.File]::Delete($tempFile)
                    } catch {
                        # Silent fail
                    }
                }
            }
        } catch {
            # Silent cleanup failure
        }
    }
    
} catch {
    Add-Content -Path $findingsFile -Value "Unable to analyze browser data: $($_.Exception.Message)"
}

Update-Progress "Checking registry artifacts..."

# Combined Registry Analysis - Optimized batch processing
Add-Section "Registry Analysis"
try {
    # Batch all registry queries together for efficiency
    $registryPaths = @{
        "MuiCache" = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
        "AppSwitched" = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched"
        "DllOpenWith" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dll\OpenWithList"
        "CompatStore" = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
    }
    
    # Get current user SID for BAM registry
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $registryPaths["BAM"] = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\$currentUser"
    
    # Process all registry locations in one pass
    $registryResults = @{
        MuiCache = @()
        AppSwitched = @()
        DllOpenWith = @()
        CompatStore = @()
        BAM = @()
    }
    
    foreach ($regType in $registryPaths.Keys) {
        try {
            $regData = Get-ItemProperty $registryPaths[$regType] -ErrorAction SilentlyContinue
            if ($regData) {
                switch ($regType) {
                    "MuiCache" {
                        $regData.PSObject.Properties | Where-Object { 
                            $_.Name -match "\.exe" -and $_.Name -notmatch "PS" -and $_.Name -notmatch "FriendlyAppName" 
                        } | ForEach-Object {
                            $exePath = ($_.Name -split '\.exe')[0] + '.exe'
                            if (-not (Test-FileSignature $exePath)) {
                                $registryResults.MuiCache += $exePath
                                Add-ExecutablePath $exePath
                            }
                        }
                    }
                    "AppSwitched" {
                        $regData.PSObject.Properties | Where-Object { 
                            $_.Name -match "\.exe" -and $_.Name -notmatch "PS" -and $_.Name -match "^[A-Za-z]:\\" 
                        } | ForEach-Object {
                            if (-not (Test-FileSignature $_.Name)) {
                                $registryResults.AppSwitched += $_.Name
                                Add-ExecutablePath $_.Name
                            }
                        }
                    }
                    "DllOpenWith" {
                        $regData.PSObject.Properties | Where-Object { $_.Name -notmatch "PS" } | ForEach-Object {
                            $registryResults.DllOpenWith += "$($_.Name) = $($_.Value)"
                        }
                    }
                    "CompatStore" {
                        $regData.PSObject.Properties | Where-Object { 
                            $_.Name -match "\.exe" -and $_.Name -notmatch "PS" -and $_.Name -match "^[A-Za-z]:\\" 
                        } | ForEach-Object {
                            if (-not (Test-FileSignature $_.Name)) {
                                $registryResults.CompatStore += $_.Name
                                Add-ExecutablePath $_.Name
                            }
                        }
                    }
                    "BAM" {
                        $regData.PSObject.Properties | Where-Object { 
                            $_.Name -match "\.exe" -and $_.Name -notmatch "PS" -and $_.Name -match "^[A-Za-z]:\\" 
                        } | ForEach-Object {
                            if (-not (Test-FileSignature $_.Name)) {
                                $registryResults.BAM += $_.Name
                                Add-ExecutablePath $_.Name
                            }
                        }
                    }
                }
            }
        } catch {
            Add-Content -Path $findingsFile -Value "Unable to access $regType registry: $($_.Exception.Message)"
        }
    }
    
    # Output all registry results in organized sections
    Add-Content -Path $findingsFile -Value "MuiCache Registry Entries:"
    if ($registryResults.MuiCache.Count -gt 0) {
        $registryResults.MuiCache | Sort-Object { $_.Length } | ForEach-Object {
            Add-Content -Path $findingsFile -Value "  $_"
        }
    } else {
        Add-Content -Path $findingsFile -Value "  No unsigned executables found"
    }
    
    Add-Content -Path $findingsFile -Value ""
    Add-Content -Path $findingsFile -Value "AppSwitched Registry Entries:"
    if ($registryResults.AppSwitched.Count -gt 0) {
        $registryResults.AppSwitched | Sort-Object { $_.Length } | ForEach-Object {
            Add-Content -Path $findingsFile -Value "  $_"
        }
    } else {
        Add-Content -Path $findingsFile -Value "  No unsigned executables found"
    }
    
    Add-Content -Path $findingsFile -Value ""
    Add-Content -Path $findingsFile -Value "DLL OpenWithList Registry Entries:"
    if ($registryResults.DllOpenWith.Count -gt 0) {
        $registryResults.DllOpenWith | ForEach-Object {
            Add-Content -Path $findingsFile -Value "  $_"
        }
    } else {
        Add-Content -Path $findingsFile -Value "  No entries found"
    }
    
    Add-Content -Path $findingsFile -Value ""
    Add-Content -Path $findingsFile -Value "BAM Registry Entries:"
    if ($registryResults.BAM.Count -gt 0) {
        $registryResults.BAM | Sort-Object { $_.Length } | ForEach-Object {
            Add-Content -Path $findingsFile -Value "  $_"
        }
    } else {
        Add-Content -Path $findingsFile -Value "  No unsigned executables found"
    }
    
    Add-Content -Path $findingsFile -Value ""
    Add-Content -Path $findingsFile -Value "Compatibility Assistant Store Entries:"
    if ($registryResults.CompatStore.Count -gt 0) {
        $registryResults.CompatStore | Sort-Object { $_.Length } | ForEach-Object {
            Add-Content -Path $findingsFile -Value "  $_"
        }
    } else {
        Add-Content -Path $findingsFile -Value "  No unsigned executables found"
    }
    
} catch {
    Add-Content -Path $findingsFile -Value "Unable to perform registry analysis: $($_.Exception.Message)"
}

Update-Progress "Optimized file system scanning..."

# Optimized File System Operations
Add-Section "Optimized File System Analysis"
try {
    # Combine all file system scans into one efficient operation
    $scanLocations = @()
    
    # Add Downloads folder
    $downloadsPath = [Environment]::GetFolderPath("UserProfile") + "\Downloads"
    if (Test-Path $downloadsPath) {
        $scanLocations += $downloadsPath
    }
    
    # Add Recent folder target resolution
    $recentPath = [Environment]::GetFolderPath("Recent")
    if (Test-Path $recentPath) {
        $scanLocations += $recentPath
    }
    
    # Add USB drives
    $usbDrives = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 }
    if ($usbDrives) {
        $usbDrives | ForEach-Object {
            if (Test-Path $_.DeviceID) {
                $scanLocations += $_.DeviceID
            }
        }
    }
    
    if ($scanLocations.Count -gt 0) {
        # Use existing cheat database if already downloaded
        if (-not $cheatDatabase) {
            Write-Host "Downloading cheat database for optimized scanning..." -ForegroundColor Cyan
            $cheatDatabase = Get-CheatDatabase
        }
        
        # Batch process all locations using pipeline optimization
        $allFiles = @()
        foreach ($location in $scanLocations) {
            try {
                if ($location.EndsWith("Recent")) {
                    # Special handling for Recent folder shortcuts
                    Get-ChildItem $location -Filter "*.lnk" -ErrorAction SilentlyContinue | ForEach-Object {
                        try {
                            $shell = New-Object -ComObject WScript.Shell
                            $shortcut = $shell.CreateShortcut($_.FullName)
                            $targetPath = $shortcut.TargetPath
                            
                            if ($targetPath -and (Test-Path $targetPath) -and $targetPath -match "\.(exe|dll|zip|rar)$") {
                                $allFiles += [PSCustomObject]@{
                                    FullName = $targetPath
                                    Extension = [System.IO.Path]::GetExtension($targetPath)
                                    Length = if (Test-Path $targetPath) { (Get-Item $targetPath -ErrorAction SilentlyContinue).Length } else { 0 }
                                    Source = "Recent"
                                }
                            }
                            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null
                        } catch {
                            # Skip problematic shortcuts
                        }
                    }
                } else {
                    # Regular file system scanning with pipeline optimization
                    Get-ChildItem $location -Recurse -File -ErrorAction SilentlyContinue | 
                        Where-Object { $_.Extension -match "\.(zip|rar|exe|dll)$" } |
                        ForEach-Object {
                            $allFiles += [PSCustomObject]@{
                                FullName = $_.FullName
                                Extension = $_.Extension
                                Length = $_.Length
                                Source = if ($location.Length -eq 3) { "USB-$location" } else { "Downloads" }
                            }
                        }
                }
            } catch {
                Add-Content -Path $findingsFile -Value "Error scanning $location`: $($_.Exception.Message)"
            }
        }
        
        # Batch process all found files
        $fileResults = @{
            detectedCheats = @()
            exe = @()
            dll = @()
            zip = @()
            rar = @()
        }
        
        # Group files by extension for optimized processing
        $fileGroups = $allFiles | Group-Object Extension
        
        foreach ($group in $fileGroups) {
            switch ($group.Name.ToLower()) {
                ".exe" {
                    $group.Group | ForEach-Object {
                        Add-ExecutablePath $_.FullName
                        
                        # Batch hash calculation
                        $fileHash = Get-FileSHA256 $_.FullName
                        if ($fileHash -and $_.Length) {
                            $lookupKey = "$fileHash|$($_.Length)"
                            
                            if ($cheatDatabase.ContainsKey($lookupKey)) {
                                $cheatName = $cheatDatabase[$lookupKey]
                                $fileResults.detectedCheats += "$($_.FullName) (*$cheatName* Detected) [$($_.Source)]"
                            } elseif (-not (Test-FileSignature $_.FullName)) {
                                $fileResults.exe += "$($_.FullName) [$($_.Source)]"
                            }
                        }
                    }
                }
                ".dll" {
                    $group.Group | ForEach-Object {
                        Add-ExecutablePath $_.FullName
                        if (-not (Test-FileSignature $_.FullName)) {
                            $fileResults.dll += "$($_.FullName) [$($_.Source)]"
                        }
                    }
                }
                ".zip" {
                    $group.Group | ForEach-Object {
                        $fileResults.zip += "$($_.FullName) [$($_.Source)]"
                    }
                }
                ".rar" {
                    $group.Group | ForEach-Object {
                        $fileResults.rar += "$($_.FullName) [$($_.Source)]"
                    }
                }
            }
        }
        
        # Output optimized results
        Add-Content -Path $findingsFile -Value "Detected Cheats (All Locations):"
        $fileResults.detectedCheats | Sort-Object | ForEach-Object {
            Add-Content -Path $findingsFile -Value "  $_"
        }
        
        Add-Content -Path $findingsFile -Value ""
        Add-Content -Path $findingsFile -Value "Unsigned Executables (All Locations):"
        $fileResults.exe | Sort-Object | ForEach-Object {
            Add-Content -Path $findingsFile -Value "  $_"
        }
        
        Add-Content -Path $findingsFile -Value ""
        Add-Content -Path $findingsFile -Value "Unsigned DLLs (All Locations):"
        $fileResults.dll | Sort-Object | ForEach-Object {
            Add-Content -Path $findingsFile -Value "  $_"
        }
        
        Add-Content -Path $findingsFile -Value ""
        Add-Content -Path $findingsFile -Value "Archive Files (All Locations):"
        ($fileResults.zip + $fileResults.rar) | Sort-Object | ForEach-Object {
            Add-Content -Path $findingsFile -Value "  $_"
        }
        
        Add-Content -Path $findingsFile -Value ""
        Add-Content -Path $findingsFile -Value "Scan Summary:"
        Add-Content -Path $findingsFile -Value "  Total files scanned: $($allFiles.Count)"
        Add-Content -Path $findingsFile -Value "  Detected cheats: $($fileResults.detectedCheats.Count)"
        Add-Content -Path $findingsFile -Value "  Unsigned executables: $($fileResults.exe.Count)"
        Add-Content -Path $findingsFile -Value "  Unsigned DLLs: $($fileResults.dll.Count)"
        Add-Content -Path $findingsFile -Value "  Archive files: $($fileResults.zip.Count + $fileResults.rar.Count)"
        
    } else {
        Add-Content -Path $findingsFile -Value "No accessible scan locations found"
    }
    
} catch {
    Add-Content -Path $findingsFile -Value "Optimized file system analysis failed: $($_.Exception.Message)"
}

Update-Progress "Performing advanced signature analysis..."

# Advanced Signature Detection System
Add-Section "Advanced Signature Analysis"
try {
    Write-Host "Performing advanced signature analysis on all discovered executables..." -ForegroundColor Cyan
    
    # Create paths.txt file with all discovered executable and DLL paths
    $pathsFilePath = Join-Path $ssPath "paths.txt"
    
    # Remove duplicates and filter valid paths
    $uniquePaths = $global:allExecutablePaths | Sort-Object -Unique | Where-Object { 
        $_ -and (Test-Path $_) -and ($_ -match "\.(exe|dll)$") 
    }
    
    if ($uniquePaths.Count -gt 0) {
        # Write all paths to the file
        $uniquePaths | Out-File -FilePath $pathsFilePath -Encoding UTF8
        
        Add-Content -Path $findingsFile -Value "Advanced signature analysis performed on $($uniquePaths.Count) executable/DLL files:"
        Add-Content -Path $findingsFile -Value ""
        
        # Perform the advanced signature detection
        $stopwatch = [Diagnostics.Stopwatch]::StartNew()
        $results = @()
        $count = 0
        $totalCount = $uniquePaths.Count
        
        foreach ($path in $uniquePaths) {
            $progress = [int]($count / $totalCount * 100)
            Write-Progress -Activity "Advanced Signature Analysis" -Status "$progress% Complete: $path" -PercentComplete $progress
            $count++
            
            try {
                $fileName = Split-Path $path -Leaf
                $signatureStatus = (Get-AuthenticodeSignature $path 2>$null).Status
                
                $fileDetails = New-Object PSObject
                $fileDetails | Add-Member NoteProperty Name $fileName
                $fileDetails | Add-Member NoteProperty Path $path
                $fileDetails | Add-Member NoteProperty SignatureStatus $signatureStatus
                
                $results += $fileDetails
                
                # Only add files with invalid/unsigned signatures to findings file
                if ($signatureStatus -ne "Valid") {
                    Add-Content -Path $findingsFile -Value "$path - Signature Status: $signatureStatus"
                }
                
            } catch {
                # Skip files that can't be processed but still record them
                Add-Content -Path $findingsFile -Value "$path - Error: Unable to check signature"
            }
        }
        
        $stopwatch.Stop()
        $time = $stopwatch.Elapsed.Hours.ToString("00") + ":" + $stopwatch.Elapsed.Minutes.ToString("00") + ":" + $stopwatch.Elapsed.Seconds.ToString("00") + "." + $stopwatch.Elapsed.Milliseconds.ToString("000")
        
        # Optimized signature analysis with parallel processing simulation
        Write-Host "Optimizing signature verification..." -ForegroundColor Cyan
        
        # Group files by directory for optimized I/O
        $pathGroups = $uniquePaths | Group-Object { Split-Path $_ -Parent }
        $optimizedResults = @()
        
        foreach ($group in $pathGroups) {
            # Process files in the same directory together for better I/O performance
            $directoryFiles = $group.Group
            foreach ($filePath in $directoryFiles) {
                try {
                    # Use faster signature check method
                    $signature = Get-AuthenticodeSignature $filePath -ErrorAction SilentlyContinue
                    $status = if ($signature) { $signature.Status } else { "Unknown" }
                    
                    $optimizedResults += [PSCustomObject]@{
                        Path = $filePath
                        Status = $status
                        Directory = $group.Name
                    }
                } catch {
                    $optimizedResults += [PSCustomObject]@{
                        Path = $filePath
                        Status = "Error"
                        Directory = $group.Name
                    }
                }
            }
        }
        
        # Group results by signature status for summary
        $validSigned = $optimizedResults | Where-Object { $_.Status -eq "Valid" }
        $invalidSigned = $optimizedResults | Where-Object { $_.Status -ne "Valid" }
        
        # Add summary section to main findings file
        Add-Content -Path $findingsFile -Value ""
        Add-Content -Path $findingsFile -Value ("=" * 50)
        Add-Content -Path $findingsFile -Value "OPTIMIZED SIGNATURE ANALYSIS SUMMARY"
        Add-Content -Path $findingsFile -Value ("=" * 50)
        Add-Content -Path $findingsFile -Value "Total files analyzed: $($optimizedResults.Count)"
        Add-Content -Path $findingsFile -Value "Valid signatures: $($validSigned.Count)"
        Add-Content -Path $findingsFile -Value "Invalid/Unsigned: $($invalidSigned.Count)"
        Add-Content -Path $findingsFile -Value "Analysis duration: $time"
        Add-Content -Path $findingsFile -Value "Optimization: Directory-grouped processing applied"
        Add-Content -Path $findingsFile -Value ""
        
        # Output detailed breakdown by directory
        Add-Content -Path $findingsFile -Value "FILES WITH INVALID/UNSIGNED SIGNATURES BY DIRECTORY:"
        $invalidByDirectory = $invalidSigned | Group-Object Directory
        foreach ($dirGroup in $invalidByDirectory) {
            Add-Content -Path $findingsFile -Value ""
            Add-Content -Path $findingsFile -Value "Directory: $($dirGroup.Name)"
            $dirGroup.Group | ForEach-Object {
                $fileName = Split-Path $_.Path -Leaf
                Add-Content -Path $findingsFile -Value "  $fileName - Status: $($_.Status)"
            }
        }
        
        Write-Host "Optimized signature analysis completed in $time" -ForegroundColor Green
        
        # Clean up paths.txt file
        if (Test-Path $pathsFilePath) {
            Remove-Item $pathsFilePath -Force -ErrorAction SilentlyContinue
        }
        
    } else {
        Add-Content -Path $findingsFile -Value "No executable or DLL files found for signature analysis"
    }
    
} catch {
    Add-Content -Path $findingsFile -Value "Unable to perform advanced signature analysis: $($_.Exception.Message)"
    
    # Cleanup on error
    $pathsFilePath = Join-Path $ssPath "paths.txt"
    if (Test-Path $pathsFilePath) {
        Remove-Item $pathsFilePath -Force -ErrorAction SilentlyContinue
    }
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
        Write-Host "Upload failed." -ForegroundColor Red
        Set-Clipboard -Value "https://filebin.net/PCCHECK$computerName$uniqueId"
        Write-Host "URL copied to clipboard!" -ForegroundColor Cyan
        Write-Host "Please check the bin to see if it failed to upload."
        Write-Host "If the upload failed, please manually upload the file."
    }
} catch {
    Write-Host "Upload failed. Error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "Press any key to return to menu..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

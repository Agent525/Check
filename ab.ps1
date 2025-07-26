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
$totalSections = 22
$currentSection = 0

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
        Get-ChildItem $prefetchPath -Filter "*.pf" | ForEach-Object {
            $prefetchResults += [PSCustomObject]@{
                Name = $_.Name
                LastWriteTime = $_.LastWriteTime
                DisplayText = "$($_.Name) - $($_.LastWriteTime)"
            }
        }
        # Sort by LastWriteTime from oldest to newest (earliest to latest)
        $prefetchResults | Sort-Object LastWriteTime | ForEach-Object {
            Add-Content -Path $findingsFile -Value $_.DisplayText
        }
    }
} catch {
    Add-Content -Path $findingsFile -Value "Unable to access Prefetch folder"
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
        & $lastActivityToolPath /scomma $lastActivityCSV
        
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
                        # Focus on "Run EXE" activities and executable files
                        $actionType = if ($entry.'Action Type') { $entry.'Action Type' } else { $entry.'Type' }
                        $filename = if ($entry.'Filename') { $entry.'Filename' } else { $entry.'File' }
                        $description = if ($entry.'Description') { $entry.'Description' } else { "" }
                        
                        # Check if this is a run executable activity or executable file
                        if (($actionType -and $actionType.ToLower().Contains("run")) -or 
                            ($filename -and $filename.ToLower().EndsWith(".exe")) -or
                            ($description -and $description.ToLower().Contains("exe"))) {
                            
                            # Extract executable path if available
                            $exePath = $filename
                            if (-not $exePath -and $description) {
                                # Try to extract path from description
                                if ($description -match '([A-Z]:\\[^"<>|*?]+\.exe)') {
                                    $exePath = $matches[1]
                                }
                            }
                            
                            if ($exePath -and $exePath.ToLower().EndsWith(".exe")) {
                                # Check if file still exists for hash calculation
                                if (Test-Path $exePath) {
                                    $fileHash = Get-FileSHA256 $exePath
                                    $fileSize = (Get-Item $exePath -ErrorAction SilentlyContinue).Length
                                    $lookupKey = "$fileHash|$fileSize"
                                    
                                    # Check against cheat database
                                    if ($cheatDatabase.ContainsKey($lookupKey)) {
                                        $cheatName = $cheatDatabase[$lookupKey]
                                        $timestamp = if ($entry.'Date/Time') { $entry.'Date/Time' } else { $entry.'Time' }
                                        $lastActivityResults.detectedCheats += "$exePath (*$cheatName* Detected) - Last Activity: $timestamp"
                                    } elseif (-not (Test-FileSignature $exePath)) {
                                        $timestamp = if ($entry.'Date/Time') { $entry.'Date/Time' } else { $entry.'Time' }
                                        $lastActivityResults.exe += "$exePath - Last Activity: $timestamp"
                                    }
                                } else {
                                    # File doesn't exist anymore, but still record the activity
                                    $timestamp = if ($entry.'Date/Time') { $entry.'Date/Time' } else { $entry.'Time' }
                                    $lastActivityResults.exe += "$exePath (File Not Found) - Last Activity: $timestamp"
                                }
                            }
                        }
                    }
                    
                    # Output detected cheats first
                    $lastActivityResults.detectedCheats | Sort-Object | Select-Object -First 50 | ForEach-Object {
                        Add-Content -Path $findingsFile -Value $_
                    }
                    
                    # Then output other executables
                    $lastActivityResults.exe | Sort-Object | Select-Object -First 50 | ForEach-Object {
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
            
            # Clean up CSV file
            Remove-Item $lastActivityCSV -ErrorAction SilentlyContinue
        } else {
            Add-Content -Path $findingsFile -Value "Last activity extraction timed out or failed"
        }
        
        # Clean up the tool
        Remove-Item $lastActivityToolPath -ErrorAction SilentlyContinue
    } else {
        Add-Content -Path $findingsFile -Value "Unable to download LastActivityView tool"
    }
} catch {
    Add-Content -Path $findingsFile -Value "Unable to analyze last activity data: $($_.Exception.Message)"
    
    # Cleanup on error
    $cleanupFiles = @(
        (Join-Path $ssPath "last_activity.csv"),
        (Join-Path $ssPath "LastActivityView.exe")
    )
    
    foreach ($file in $cleanupFiles) {
        if (Test-Path $file) {
            Remove-Item $file -Force -ErrorAction SilentlyContinue
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
        "wh-satano.ru", "susano.re", "vape.gg", "neverlack.in", "liquidbounce.net"
    )
    $suspiciousDomains = @(".gg", ".cc", ".io", ".wtf", ".ru")
    
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
        
        # Clean up NirSoft tools
        if (Test-Path $historyToolPath) { Remove-Item $historyToolPath -ErrorAction SilentlyContinue }
        if (Test-Path $downloadsToolPath) { Remove-Item $downloadsToolPath -ErrorAction SilentlyContinue }
        
        # Additional cleanup - ensure all temporary files are removed
        $tempFiles = @(
            (Join-Path $ssPath "browser_history.csv"),
            (Join-Path $ssPath "browser_downloads.csv"),
            (Join-Path $ssPath "BrowsingHistoryView.exe"),
            (Join-Path $ssPath "BrowserDownloadsView.exe")
        )
        
        foreach ($tempFile in $tempFiles) {
            if (Test-Path $tempFile) {
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            }
        }
        
    } catch {
        Add-Content -Path $findingsFile -Value "Unable to download or execute browser analysis tools: $($_.Exception.Message)"
        
        # Cleanup on error as well
        $tempFiles = @(
            (Join-Path $ssPath "browser_history.csv"),
            (Join-Path $ssPath "browser_downloads.csv"),
            (Join-Path $ssPath "BrowsingHistoryView.exe"),
            (Join-Path $ssPath "BrowserDownloadsView.exe")
        )
        
        foreach ($tempFile in $tempFiles) {
            if (Test-Path $tempFile) {
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
} catch {
    Add-Content -Path $findingsFile -Value "Unable to analyze browser data: $($_.Exception.Message)"
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
    $currentUser = [System.Security.Principal]::GetCurrent().User.Value
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
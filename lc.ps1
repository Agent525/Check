#Requires -RunAsAdministrator

# Live Checker - System Status Check

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script requires Administrator privileges!" -ForegroundColor Red
    Write-Host "Please restart PowerShell as Administrator and try again." -ForegroundColor Yellow
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

# Clear screen and set up display
Clear-Host

# Function to center text
function Write-CenteredText {
    param(
        [string]$Text,
        [string]$Color = "White",
        [switch]$NoNewline
    )
    $consoleWidth = $Host.UI.RawUI.WindowSize.Width
    $padding = [Math]::Max(0, ($consoleWidth - $Text.Length) / 2)
    $centeredText = (" " * $padding) + $Text
    
    if ($NoNewline) {
        Write-Host $centeredText -ForegroundColor $Color -NoNewline
    } else {
        Write-Host $centeredText -ForegroundColor $Color
    }
}

Write-Host $header -ForegroundColor Cyan
Write-Host ""

# Function to get colored status
function Get-StatusColor {
    param($Status)
    switch ($Status.ToLower()) {
        "running" { return "Green" }
        "stopped" { return "Red" }
        "present" { return "Green" }
        "not present" { return "Yellow" }
        default { return "White" }
    }
}

# Function to format and display service status
function Show-ServiceStatus {
    param($ServiceName, $Status, $DisplayName = $ServiceName)
    $color = Get-StatusColor $Status
    $statusFormatted = $Status.PadRight(10)
    $line = "  $($DisplayName.PadRight(25)): $statusFormatted"
    Write-CenteredText $line -Color White
}

# Function to display drive information
function Show-DriveInfo {
    param($Drive, $FileSystem, $USNStatus)
    $fileSystemColor = if ($FileSystem -eq "NTFS") { "Green" } else { "Yellow" }
    $usnColor = Get-StatusColor $USNStatus
    
    $line = "  Drive $($Drive.PadRight(3)): $($FileSystem.PadRight(8)) | USN Journal: $USNStatus"
    Write-CenteredText $line -Color White
}

# Get OS Install Date
try {
    $osInstallDate = (Get-CimInstance Win32_OperatingSystem).InstallDate
    $installDateFormatted = $osInstallDate.ToString("yyyy-MM-dd HH:mm:ss")
    $osLine = "OS Install Date: $installDateFormatted"
    Write-CenteredText $osLine -Color Yellow
} catch {
    Write-CenteredText "OS Install Date: Unable to retrieve" -Color Red
}

Write-Host ""
Write-CenteredText ("=" * 65) -Color Cyan
Write-CenteredText "SERVICE STATUS" -Color Cyan
Write-CenteredText ("=" * 65) -Color Cyan

# Services to monitor
$servicesToCheck = @(
    @{Name="PcaSvc"; Display="Program Compatibility"},
    @{Name="DPS"; Display="Diagnostic Policy"},
    @{Name="DiagTrack"; Display="Diagnostic Tracking"},
    @{Name="SysMain"; Display="SysMain (Superfetch)"},
    @{Name="EventLog"; Display="Windows Event Log"},
    @{Name="SgrmBroker"; Display="System Guard Runtime"},
    @{Name="CDPUserSvc"; Display="Connected Devices"},
    @{Name="AppInfo"; Display="Application Information"},
    @{Name="WSearch"; Display="Windows Search"},
    @{Name="VSS"; Display="Volume Shadow Copy"}
)

# Check each service
foreach ($serviceInfo in $servicesToCheck) {
    try {
        # Handle CDPUserSvc (per-user service)
        if ($serviceInfo.Name -eq "CDPUserSvc") {
            # Get all CDPUserSvc instances
            $cdpServices = Get-Service -Name "CDPUserSvc*" -ErrorAction SilentlyContinue
            if ($cdpServices) {
                $runningCount = ($cdpServices | Where-Object { $_.Status -eq "Running" }).Count
                $totalCount = $cdpServices.Count
                $status = if ($runningCount -gt 0) { "Running ($runningCount/$totalCount)" } else { "Stopped" }
                Show-ServiceStatus $serviceInfo.Name $status $serviceInfo.Display
            } else {
                Show-ServiceStatus $serviceInfo.Name "Not Found" $serviceInfo.Display
            }
        } else {
            # Check if service exists first
            $service = Get-Service -Name $serviceInfo.Name -ErrorAction SilentlyContinue
            if ($service) {
                $status = $service.Status.ToString()
                Show-ServiceStatus $serviceInfo.Name $status $serviceInfo.Display
            } else {
                # Try alternative service names or check if service is disabled/removed
                $allServices = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$($serviceInfo.Name)*" -or $_.DisplayName -like "*$($serviceInfo.Display)*" }
                if ($allServices) {
                    $status = $allServices[0].Status.ToString()
                    Show-ServiceStatus $serviceInfo.Name $status $serviceInfo.Display
                } else {
                    Show-ServiceStatus $serviceInfo.Name "Not Found" $serviceInfo.Display
                }
            }
        }
    } catch {
        # More detailed error information
        $errorMsg = "Error: $($_.Exception.Message)"
        Show-ServiceStatus $serviceInfo.Name $errorMsg $serviceInfo.Display
    }
}

Write-Host ""
Write-CenteredText ("=" * 65) -Color Cyan
Write-CenteredText "DRIVE AND USN JOURNAL STATUS" -Color Cyan
Write-CenteredText ("=" * 65) -Color Cyan

# Get drive information
try {
    $drives = Get-WmiObject Win32_LogicalDisk | Sort-Object DeviceID
    
    foreach ($drive in $drives) {
        $driveLetter = $drive.DeviceID
        $fileSystem = if ($drive.FileSystem) { $drive.FileSystem } else { "Unknown" }
        
        # Check USN Journal for NTFS drives
        $usnStatus = "N/A"
        if ($fileSystem -eq "NTFS") {
            try {
                $driveLetterOnly = $driveLetter.TrimEnd(':')
                $usnInfo = fsutil usn queryjournal $driveLetter 2>$null
                if ($LASTEXITCODE -eq 0) {
                    $usnStatus = "Present"
                } else {
                    $usnStatus = "Not Present"
                }
            } catch {
                $usnStatus = "Unknown"
            }
        }
        
        Show-DriveInfo $driveLetter $fileSystem $usnStatus
    }
} catch {
    Write-CenteredText "Error retrieving drive information" -Color Red
}

Write-Host ""
Write-CenteredText ("=" * 65) -Color Cyan
$completionLine = "Scan completed: " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Write-CenteredText $completionLine -Color Yellow
Write-CenteredText ("=" * 65) -Color Cyan
Write-Host ""
Write-CenteredText "Press any key to exit..." -Color Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# "Anti-Bypass" Universal PC Checking Tool

A comprehensive PowerShell-based security analysis tool designed for digital forensic analysts to perform thorough system investigations and forensic analysis.

## Features

### Core Analysis Capabilities
- **System Information**: Boot security, DMA protection, virtualization status
- **Drive Analysis**: File system enumeration and USN Journal status
- **USB & PCIE Device Detection**: Hardware enumeration with vendor/device ID extraction
- **Service Status Monitoring**: Critical Windows services (DPS, PcaSvc, AppInfo, EventLog, BAM, SysMain)
- **Browser Detection**: Multi-browser support (Chrome, Firefox, Edge, Opera, Opera GX, Brave)
- **File Analysis**: Downloads folder scanning for executables, archives, and unsigned files
- **Registry Forensics**: MuiCache, AppSwitched, BAM, and Compatibility Assistant analysis
- **Prefetch Analysis**: Windows prefetch file examination
- **Event Log Monitoring**: USN Journal deletion event detection
- **Deleted File Recovery**: Recycle bin artifact analysis

### Additional Tools
- **PC Check Tools Downloader**: Automated download of Tech's Technical Utility
- **Moss File Checker**: Specialized file integrity verification tool for MOSS Anticheat
- **Filebin Integration**: Automatic report upload with unique identifiers
- **Filebin Management**: Delete previous analysis bins for user privacy

## Requirements

- Windows 10/11
- PowerShell 5.1 or later
- Administrator privileges (Required)
- Internet connection (for tool downloads and report uploads)

## Installation/Usage

1. Simply open a windows terminal as administrator and run the following command

```
Clear-Host; $consent = Read-Host "Do you wish to download and execute the script? (y/n)"; if ($consent -eq 'y') { iex (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Agent525/Check/refs/heads/main/ab.ps1").Content } else { Write-Host "Script execution cancelled." }
```

### Menu Options

```
[1] Download PC Check Tools Downloader
[2] Download Moss File Checker  
[3] Run Generic Analysis
[4] Delete Previous Filebin
```

#### Option 1: PC Check Tools Downloader
Downloads TechTool.exe from the repository to `C:\SS\`

#### Option 2: Moss File Checker
Downloads MossCheck.cmd for specialized file verification to `C:\SS\`

#### Option 3: Generic Analysis
Performs comprehensive system analysis including:
- System security status
- Hardware enumeration
- File system analysis
- Registry forensics
- Event log examination
- Evidence collection

#### Option 4: Delete Previous Filebin
Removes previously uploaded analysis reports from filebin.net

## Output

### Local Storage
- Analysis results saved to: `C:\SS\FindingsMM-DD.txt`
- Downloaded tools stored in: `C:\SS\`

### Remote Upload
- Automatic upload to filebin.net
- URL format: `https://filebin.net/PCCHECK[COMPUTERNAME][XXX]`
- Unique 3-digit alphanumeric identifier for each analysis
- URL automatically copied to clipboard

## Analysis Sections

| Section | Description |
|---------|-------------|
| **Drive Letters** | File system types and drive enumeration |
| **USN Journal** | NTFS change journal status per drive |
| **USN Journal Deletion Events** | Event ID 3079 monitoring |
| **Windows Defender Exclusions** | Path, extension, and process exclusions |
| **Windows Defender Alerts** | Recent malware detection events |
| **Installed Antivirus Software** | Detection of common AV solutions |
| **USB Devices** | Connected USB hardware with vendor IDs |
| **PCIE Devices** | PCI Express hardware enumeration |
| **Windows Services Status** | Critical service monitoring |
| **Installed Browsers** | Browser detection and paths |
| **USB Drives Scan** | Complete USB drive content analysis with cheat detection |
| **Downloads** | Suspicious file analysis in Downloads folder with signature checking |
| **Prefetch Files** | Windows prefetch examination |
| **Recent Files** | Shell:recent folder analysis with cheat detection |
| **Browser History and Downloads** | **ENHANCED:** Advanced browser analysis using NirSoft tools |
| **MuiCache** | Registry execution artifacts |
| **AppSwitched** | Application switching history |
| **DLL OpenWithList** | DLL association analysis |
| **BAM Registry** | Background Activity Moderator entries |
| **Compatibility Assistant Store** | Application compatibility data |
| **Recently Deleted Files** | Recycle bin artifact recovery |

## Security Features

- **Digital Signature Verification**: Automatic validation of executable files
- **Unsigned Binary Detection**: Identification of potentially suspicious executables
- **Hardware Tampering Detection**: USB and PCIE device monitoring
- **Windows Defender Analysis**: Exclusion and alert monitoring
- **Antivirus Detection**: Common security software identification
- **Evidence Preservation**: Comprehensive logging and documentation
- **Anti-Bypass Mechanisms**: Detection of common evasion techniques

## File Formats Analyzed

- **Executables**: `.exe` files with signature validation
- **Archives**: `.zip`, `.rar` files
- **Prefetch**: `.pf` Windows prefetch files
- **Registry**: Multiple hives and keys
- **Event Logs**: Windows Application log analysis

## Supported Browsers

- Google Chrome (x86/x64)
- Mozilla Firefox (x86/x64)
- Microsoft Edge
- Opera (x86/x64)
- Opera GX (x86/x64)
- Brave Browser (x86/x64)

## Technical Details

### USB Device Format
```
USB Hub: [Device Name] - USB - Vendor ID: [XXXX] Device ID: [XXXX]
```

### PCIE Device Format
```
PCIE Device: [Device Name] - PCI - Vendor ID: [XXXX] Device ID: [XXXX]
```

### Progress Tracking
- 22 total analysis sections
- Real-time progress indication
- Error handling with graceful degradation

## Troubleshooting

### Common Issues

**Script Execution Blocked**
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

**Upload Failures**
- Check internet connectivity
- Verify curl.exe availability in System32
- Manual upload option provided

`Note: It may say failure to upload yet still upload. Check first before moving on`


**Access Denied Errors**
- Ensure Administrator privileges
- Check Windows Defender exclusions
- Verify NTFS permissions

### Log Analysis

Review the generated `FindingsMM-DD.txt` file for:
- Error messages in each section
- "Unable to access" indicators
- Missing or corrupted data

## Best Practices

1. **Run as Administrator**: Always execute with elevated privileges
2. **Evidence Chain**: Maintain proper documentation of analysis timestamps
3. **Regular Updates**: Keep the tool updated for latest detection capabilities
4. **Backup Results**: Save analysis files before deletion

## Changelog

### Current Version Features
- Enhanced USB/PCIE device ID parsing
- USN Journal deletion event monitoring
- Windows Defender exclusions and alerts analysis
- Common antivirus software detection (McAfee, Malwarebytes, Bitdefender, Kaspersky, Norton, Avast, AVG, TotalAV)
- Improved browser detection (Opera GX support)
- Automated filebin management
- Digital signature validation
- Comprehensive error handling
- **Signature-Based Cheat Detection** across multiple locations
  - **Real-time database download** from GitHub repository
  - **SHA256 hash verification** of executable files
  - **File size matching** for enhanced accuracy
  - **Automatic cheat identification** with naming conventions
  - **Prioritized reporting** - detected cheats appear at the top of relevant sections
  - **Multi-location scanning** - Downloads folder, USB drives, and Recent files
- **Recent Files Analysis**
  - **Shell:recent folder scanning** for recently accessed files
  - **Shortcut resolution** to identify actual file locations
  - **Multi-format support** for .exe, .dll, .zip, .rar files
  - **Integrated cheat detection** with signature database
  - **Digital signature verification** for executables and DLLs
- **NEW: Browser History Extraction**
  - **Multi-browser support** for Chrome, Firefox, Edge, Opera, Brave, Opera GX
  - **Advanced filtering** to exclude advertising and extension URLs
  - **Keyword-based detection** for cheat-related terms (cheat, loader, injector, aimbot, etc.)
  - **Suspicious domain filtering** (.gg, .cc, .io, .wtf, .ru domains)
  - **Automated exclusions** for googleadservices, extensions, and browser internal URLs
  - **PowerShell-native parsing** for reliable data extraction without external dependencies
  - **URL pattern extraction** from browser database files
  - **Multi-profile Firefox support** with automatic profile detection
  - **Database lock handling** through temporary file creation
  - **Comprehensive error handling** for corrupted or inaccessible databases
  - **Top 50 unique suspicious URLs** per browser for focused analysis
- **ENHANCED: Browser History and Downloads Analysis**
  - **NirSoft BrowsingHistoryView integration** for comprehensive history extraction
  - **NirSoft BrowserDownloadsView integration** for detailed download analysis
  - **Multi-browser support** including Chrome, Firefox, IE, Safari, Edge, Opera, Brave
  - **30-day historical data** extraction and analysis
  - **Advanced filtering** for cheat-related keywords and suspicious domains
  - **Download pattern analysis** including filename and URL inspection
  - **Automated tool deployment** - tools downloaded, executed, and cleaned up automatically
  - **CSV data parsing** for accurate information extraction
  - **Suspicious domain detection** (.gg, .cc, .io, .wtf, .ru)
  - **Keyword-based detection** (cheat, loader, injector, aimbot, etc.)
  - **Exclusion filtering** for ads and browser extensions
  - **Combined history and download correlation** for comprehensive browser forensics

## Supported Antivirus Software

- McAfee
- Malwarebytes
- Bitdefender
- Kaspersky
- Norton/NortonLifeLock
- Avast
- AVG
- TotalAV

## Support

For issues, feature requests, or contributions, please refer to the project repository or contact the development team.

## Legal Notice

This tool is intended for authorized security testing, forensic analysis, and system administration purposes only. Users are responsible for compliance with applicable laws and regulations.

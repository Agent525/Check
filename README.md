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

`iex (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Agent525/Check/refs/heads/main/ab.ps1").Content`

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
| **USB Devices** | Connected USB hardware with vendor IDs |
| **PCIE Devices** | PCI Express hardware enumeration |
| **Windows Services Status** | Critical service monitoring |
| **Installed Browsers** | Browser detection and paths |
| **Downloads** | Suspicious file analysis in Downloads folder |
| **Prefetch Files** | Windows prefetch examination |
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
- 16 total analysis sections
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
- Improved browser detection (Opera GX support)
- Automated filebin management
- Digital signature validation
- Comprehensive error handling

## Support

For issues, feature requests, or contributions, please refer to the project repository or contact the development team.

## Legal Notice

This tool is intended for authorized security testing, forensic analysis, and system administration purposes only. Users are responsible for compliance with applicable laws and regulations.

# "Anti-Bypass" Universal PC Checking Tool

A comprehensive PowerShell-based security analysis tool designed for digital forensic analysts to perform thorough system investigations and forensic analysis.

## Features

### Core Analysis Capabilities
- **System Security Analysis**: Boot security, hardware protection, virtualization status
- **Drive Analysis**: File system enumeration and integrity checking
- **Hardware Detection**: USB & PCIE device enumeration with identification
- **Service Monitoring**: Critical Windows services status verification
- **Browser Analysis**: Multi-browser support and activity detection
- **File Analysis**: Comprehensive file scanning and signature validation
- **Registry Forensics**: Windows registry artifact analysis
- **System Artifacts**: Prefetch analysis and event log monitoring
- **Evidence Recovery**: Deleted file artifact analysis

### Additional Tools
- **PC Check Tools Downloader**: Automated download of specialized utilities
- **Moss File Checker**: File integrity verification tool
- **Filebin Integration**: Automatic report upload with unique identifiers
- **Filebin Management**: Delete previous analysis reports

## Requirements

- Windows 10/11
- PowerShell 5.1 or later
- Administrator privileges (Required)
- Internet connection (for tool downloads and report uploads)

## Installation/Usage

1. Open Windows Terminal as administrator and run:

```
Clear-Host; Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process; $consent = Read-Host "Do you wish to download and execute the script? (y/n)"; if ($consent -eq 'y') { iex (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Agent525/Check/refs/heads/main/ab.ps1").Content } else { Write-Host "Script execution cancelled." }
```

### Menu Options

```
[1] Download PC Check Tools Downloader
[2] Download Moss File Checker  
[3] Run Generic Analysis
[4] Delete Previous Filebin
```

## Output

### Local Storage
- Analysis results saved to: `C:\SS\FindingsMM-DD.txt`
- Downloaded tools stored in: `C:\SS\`

### Remote Upload
- Automatic upload to filebin.net
- URL format: `https://filebin.net/PCCHECK[COMPUTERNAME][XXX]`
- Unique 3-digit alphanumeric identifier for each analysis
- URL automatically copied to clipboard

## Supported Platforms

- Google Chrome, Firefox, Edge, Opera, Opera GX, Brave
- Multiple antivirus solutions
- Various file formats and archives
- Windows registry hives and event logs

## Technical Details

- 22+ comprehensive analysis sections
- Real-time progress indication
- Advanced error handling and recovery
- Digital signature verification
- Hardware fingerprinting

## Troubleshooting

### Common Issues

**Script Execution Blocked**
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

**Upload Failures**
- Check internet connectivity
- Verify system requirements
- Manual upload option available

**Access Denied Errors**
- Ensure Administrator privileges
- Check security software settings
- Verify file system permissions

### Log Analysis

Review generated reports for:
- System security status
- Hardware configuration
- Software activity patterns
- Potential security concerns

## Best Practices

1. **Run as Administrator**: Always execute with elevated privileges
2. **Evidence Chain**: Maintain proper documentation of analysis timestamps
3. **Regular Updates**: Keep the tool updated for latest detection capabilities
4. **Secure Handling**: Protect analysis results appropriately

## Legal Notice

This tool is intended for authorized security testing, forensic analysis, and system administration purposes only. Users are responsible for compliance with applicable laws and regulations.

For support, feature requests, or contributions, please refer to the project repository.
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
  - **Keyword-based detection** for cheat-related terms
  - **Suspicious domain filtering** 
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
  - **Enhanced keyword detection** including "bypass" and "cdn.discordapp.com" patterns
  - **Download pattern analysis** including filename and URL inspection
  - **Improved timing control** - waits for CSV generation before parsing
  - **Automated tool deployment** - tools downloaded, executed, and cleaned up automatically
  - **CSV data parsing** with timeout protection and error handling
  - **Suspicious domain detection** (.gg, .cc, .io, .wtf, .ru)
  - **Comprehensive keyword detection** (cheat, loader, injector, aimbot, bypass, cdn.discordapp.com, etc.)
  - **Enhanced exclusion filtering** for ads, browser extensions, Google accounts, and tracking domains
  - **Clean Discord CDN display** - simplified filename presentation for Discord downloads
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

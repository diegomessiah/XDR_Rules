# SentinelOne XDR Rules

## **Persistence & Credential Access**
- **Abusing Windows Telemetry For Persistence**: Monitors abuse of Microsoft Compatibility Appraiser for persistence.
- **Access of Stored Browser Credentials**: Detects attempts to access stored browser credentials.
- **WDigest Usage to Store ClearText Creds via Registry**: Detects modifications to WDigest registry settings for credential theft.
- **DumpStack.log Defender Evasion**: Detects use of the DumpStack.log file to evade Windows Defender.

## **Active Directory & Enumeration**
- **Active Directory Attack via Powershell Exploit**: Detects PowerShell attacks on Active Directory.
- **Usage of 'Get-ADUser' Users Enumeration**: Detects enumeration of AD users via `Get-ADUser`.
- **Admins Group Enumeration**: Monitors commands enumerating Admins group.
- **BazarLoader dumps AD info**: Detects BazarLoader dumping AD data.

## **Exploitation & Ransomware**
- **ADCSPwn Hack Tool**: Detects ADCSPwn tool targeting Active Directory Certificate Services.
- **BlackByte Ransomware**: Identifies BlackByte ransomware activity.
- **Snatch Ransomware**: Detects Snatch ransomware execution and service manipulation.
- **Moses Staff Campaign**: Identifies activity linked to Moses Staff campaign.

## **Remote Execution & Living Off The Land (LOLBins)**
- **WinRM Command-Line WMI Process Creation**: Detects process execution via WinRM using WMI.
- **Possible Powershell Downgrade Attack**: Monitors PowerShell version downgrade attempts.
- **PowerShell Net.WebClient Detected**: Detects PowerShell downloading content using `Net.WebClient`.

## **Firewall & Security Bypass**
- **Usage of 'Set-NetFirewallProfile' to Disable FW**: Detects disabling Windows Firewall via PowerShell.
- **Disable Windows Firewall via Command Line**: Detects firewall disabling attempts.
- **Disable Edge Phishing Filter**: Detects Edge phishing filter modifications.
- **Disable SmartScreen - Windows**: Monitors disabling SmartScreen protections.

## **Obfuscation & Execution**
- **PowerShell String Concatenation Bypass in Function Call**: Detects PowerShell obfuscation using string concatenation.
- **PowerShell Execution Bypass Detected**: Detects execution policy bypass in PowerShell.
- **PowerShell Inline Alternative Execution Bypass**: Blocks alternative execution techniques in PowerShell.
- **Execute LOLBIN - rundll32.exe advpack.dll,RegisterOCX**: Blocks rundll32 abuse with `advpack.dll`.

## **Data Exfiltration & Backup Tampering**
- **Wbadmin Delete Systemstatebackup**: Detects deletion of Windows system state backups.
- **Windows Crypto Mining Indicators**: Detects PowerShell commands used for cryptomining.
- **Copying Sensitive Files with Credential Data**: Detects copying of files containing credentials.
- **DNS Exfiltration and Tunneling Tools Execution**: Monitors execution of DNS exfiltration tools.

## **Suspicious Application Behavior**
- **Suspicious MS Office Child Process**: Detects unusual child processes spawned by MS Office.
- **Suspicious 7zip Subprocess**: Detects suspicious subprocesses involving 7zip.
- **SysInternals Junction.exe Symbolic Link Tool**: Detects use of `junction.exe` for symbolic links.
- **AnyDesk Silent Installation Detected**: Detects silent AnyDesk installations.


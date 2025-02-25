# SentinelOne XDR Rules

## **Persistence & Credential Access**
- **Abusing Windows Telemetry For Persistence**: Monitors abuse of Microsoft Compatibility Appraiser for persistence.
- **Access of Stored Browser Credentials**: Detects attempts to access stored browser credentials.
- **WDigest Usage to Store ClearText Creds via Registry**: Detects modifications to WDigest registry settings for credential theft.
- **DumpStack.log Defender Evasion**: Detects use of the DumpStack.log file to evade Windows Defender.
- **Dropping Of Password Filter DLL**: Detects password filter DLL additions to LSA registry key for persistence.
- **Clear Windows Audit Policy Config**: Monitors attempts to clear Windows audit policy configuration.

## **Active Directory & Enumeration**
- **Active Directory Attack via Powershell Exploit**: Detects PowerShell attacks on Active Directory.
- **Usage of 'Get-ADUser' Users Enumeration**: Detects enumeration of AD users via `Get-ADUser`.
- **Admins Group Enumeration**: Monitors commands enumerating Admins group.
- **BazarLoader dumps AD info**: Detects BazarLoader dumping AD data.

## **Exploitation & Ransomware**
- **ADCSPwn Hack Tool**: Detects ADCSPwn tool targeting Active Directory Certificate Services.
- **BlackByte Ransomware**: Identifies BlackByte ransomware activity.
- **Snatch Ransomware**: Detects Snatch ransomware execution and service manipulation.
- **Apostle Ransomware using OrcusRAT**: Detects Apostle ransomware activity via DNS ServerLevelPluginDll.
- **Moses Staff Campaign**: Identifies activity linked to Moses Staff campaign.

## **Remote Execution & Living Off The Land (LOLBins)**
- **WinRM Command-Line WMI Process Creation**: Detects process execution via WinRM using WMI.
- **Possible Powershell Downgrade Attack**: Monitors PowerShell version downgrade attempts.
- **PowerShell Net.WebClient Detected**: Detects PowerShell downloading content using `Net.WebClient`.
- **Execute LOLBIN - rundll32.exe advpack.dll,RegisterOCX**: Blocks rundll32 abuse with `advpack.dll`.
- **Execute LOLBIN - rundll32.exe pcwutl.dll,LaunchApplication**: Detects rundll32 abuse with `pcwutl.dll`.
- **Execute LOLBIN - rundll32.exe url.dll,FileProtocolHandler**: Detects rundll32 abuse with `url.dll`.

## **Firewall & Security Bypass**
- **Usage of 'Set-NetFirewallProfile' to Disable FW**: Detects disabling Windows Firewall via PowerShell.
- **Disable Windows Firewall via Command Line**: Detects firewall disabling attempts.
- **Disable Edge Phishing Filter**: Detects Edge phishing filter modifications.
- **Disable SmartScreen - Windows**: Monitors disabling SmartScreen protections.
- **Block PowerShell from Changing WindowsDefender Settings**: Prevents PowerShell modifications to Defender settings.
- **Block Setting Image File Execution Debugger**: Blocks changes to Image File Execution Debugger, used for persistence.

## **Obfuscation & Execution**
- **PowerShell String Concatenation Bypass in Function Call**: Detects PowerShell obfuscation using string concatenation.
- **PowerShell Execution Bypass Detected**: Detects execution policy bypass in PowerShell.
- **PowerShell Inline Alternative Execution Bypass**: Blocks alternative execution techniques in PowerShell.
- **PowerShell Advanced WebClient and DownloadString**: Detects and blocks PowerShell obfuscation with WebClient.
- **Detect CMD Echoing DOTNET Code into a File**: Blocks command-line techniques to echo .NET code into files.
- **Hidden Powershell in Link File Pattern**: Detects PowerShell execution via `.lnk` files.
- **Impacket Heuristic Detections**: Detects heuristic indicators of Impacket tool usage.

## **Data Exfiltration & Backup Tampering**
- **Wbadmin Delete Systemstatebackup**: Detects deletion of Windows system state backups.
- **Windows Crypto Mining Indicators**: Detects PowerShell commands used for cryptomining.
- **Copying Sensitive Files with Credential Data**: Detects copying of files containing credentials.
- **DNS Exfiltration and Tunneling Tools Execution**: Monitors execution of DNS exfiltration tools.
- **DNS ServerLevelPluginDll Install**: Detects installation of malicious DNS ServerLevelPluginDll.

## **Scheduled Tasks & Registry Changes**
- **Detect Scheduled Tasks Created to run at LOGON**: Detects scheduled tasks configured to execute at logon.
- **Detect Generic Reg Add RunOnce**: Monitors registry modifications for persistence.
- **Disable Event Logging with wevtutil**: Detects attempts to disable Windows event logs.
- **Possibly Suspicious Regsvc Registry Modification**: Detects registry changes affecting `Regsvc`.

## **Suspicious Application Behavior**
- **Suspicious MS Office Child Process**: Detects unusual child processes spawned by MS Office.
- **Suspicious 7zip Subprocess**: Detects suspicious subprocesses involving 7zip.
- **SysInternals Junction.exe Symbolic Link Tool**: Detects use of `junction.exe` for symbolic links.
- **AnyDesk Silent Installation Detected**: Detects silent AnyDesk installations.
- **Bitsadmin Usage Detected**: Monitors usage of `bitsadmin` for potential abuse.
- **Block MSBuild on User Endpoints**: Blocks execution of MSBuild on non-developer systems.

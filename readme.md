| **Rule name**  | Description |
Abusing Windows Telemetry For Persistence |**   | Monitors for commands abusing Windows Telemetry tasks, such as Microsoft Compatibility Appraiser, for persistence, excluding specific legitimate patterns.
Access of Stored Browser Credentials**   | Monitors process command line for access to stored browser credentials.
| **Active Directory Attack via Powershell Exploit** |**   | Monitors for PowerShell commands targeting Active Directory vulnerabilities or sensitive data, indicating potential exploitation.
| **ADCSPwn Hack Tool** |**   | Monitors for the use of ADCSPwn hack tool, which exploits Active Directory Certificate Services vulnerabilities, using specific command line patterns.
Admins Group Enumeration |**   | Monitors for command lines attempting to enumerate the Admins group.
AnyDesk Silent Installation Detected**   | Monitors for silent installation of AnyDesk using specific command line patterns, which may indicate unauthorized remote access setup.
Apostle Ransomware using OrcusRAT**   | Detection of potentially malicious activity related to DNS ServerLevelPluginDll Install.
Atomic #1 - Indirect Command Execution - pcalua.exe**   | Monitors for indirect command execution using pcalua.exe -a
Atomic #22 - Disable UAC AdminPromptBehavior By RegKey**   | Monitors for commands attempting to disable UAC AdminPromptBehavior by modifying the registry key.
Atomic Test #2 - Detect Virtualization Environment**   | Monitors for commands attempting to detect a virtualization environment by querying thermal zone temperature.
Atomic Test #3 - Bypass UAC using Fodhelper**   | Monitors for commands attempting to bypass UAC using Fodhelper by modifying the registry key.
Atomic Test #7 - Bypass UAC using sdclt DelegateExecute**   | Monitors for commands attempting to bypass UAC using sdclt DelegateExecute by modifying the registry key.
Atomic Test #8 - Disable UAC using reg.exe**   | Monitors for commands attempting to disable UAC using reg.exe by modifying the registry key.
Base64 Encoded Listing of Shadowcopy**   | Detection of potentially malicious activity related to DNS Exfiltration and Tunneling Tools Execution.
BazarLoader dumps AD info**   | Monitors for command lines indicating the dumping of Active Directory information by BazarLoader, which targets files like pwddump.txt and users.csv.
Bitsadmin Usage Detected**   | Monitors for usage of bitsadmin command, which can be used for malicious purposes.
BlackByte Ransomware**   | Monitors for command lines indicative of BlackByte Ransomware activities.
Block desktopimgdownldr LOLBin**   | This rule blocks the download of LOLBIN using the desktopimgdownldr utility, preventing misuse of this legitimate binary.
Block LOLBIN certutil.exe -decode**   | This rule blocks the use of LOLBIN certutil.exe with the -decode flag, which can be used to decode malicious payloads.
Block MSBuild on User Endpoints**   | This rule blocks the use of MSBuild on user endpoints, a technique that can be used by attackers to compile and execute malicious code.
Block Office from executing Alternative PowerShell**   | This rule prevents Office applications from executing alternative PowerShell scripts, which can be used to bypass traditional security controls.
Block PowerShell from Changing WindowsDefender Settings**   | This rule blocks PowerShell from changing Windows Defender settings, preventing potential tampering with security configurations.
Block PowerShell Invoke-Web-Request via Inline Command-Line**   | This rule detects and blocks the use of PowerShell invoke-web-request with inline command-line, a technique used to download malicious payloads.
Block Reg Add Disabling Windows Defender**   | This rule detects and blocks the use of PowerShell advanced WebClient and download string, which can be used to download malicious files.
Block Setting Image File Execution Debugger**   | This rule prevents the setting of the Image File Execution Debugger, a technique used by attackers to intercept and manipulate the execution of processes.
Block Windows Defender DownloadFile LOLBin**   | This rule blocks Windows Defender from downloading LOLBIN, preventing potential bypass of security measures using trusted binaries.
Boot Values Being Potentially Edited**   | Monitors for commands that may indicate boot values are being edited.|
Clear Windows Audit Policy Config**   | Monitors for commands attempting to clear Windows audit policy configuration.
CobaltStrike Load by Rundll32**   | Monitors for command lines indicating the use of rundll32.exe to load CobaltStrike, which may indicate malicious activity leveraging the StartW function in DLL files.
COMPlus_ETWEnabled Command Line Arguments**   | Monitors for command lines setting COMPlus_ETWEnabled to 0, which may indicate attempts to disable Event Tracing for Windows (ETW) for evasion purposes.
Copying Sensitive Files with Credential Data**   | Monitors for command lines using esentutl.exe to copy sensitive files containing credential data, which may indicate credential dumping activities.
Creation of Named Pipe Detected**   | Monitors for commands indicating the creation of named pipes.
CVE-2021-26857 Exchange Exploitation**   | Monitors for the exploitation of CVE-2021-26857 in Exchange Server by checking for MWorkerProcess.exe activity, excluding specific legitimate patterns.
Detect and Block PowerSharpPack PowerShell Scripts**   | This rule detects and blocks the execution of PowerSharpPack PowerShell scripts, a toolkit used for post-exploitation activities.
Detect CMD Echoing DOTNET Code into a File**   | This rule blocks the use of CMD to echo .NET code into files, a technique used to create and execute malicious .NET applications.
Detect Creation of Symbolic Links**   | This rule detects the creation of symbolic links, which can be used by attackers to bypass file system restrictions and access unauthorized files.
Detect Generic Reg Add RunOnce**   | This rule detects the use of generic registry add RunOnce commands, which can be used by malware to achieve persistence.
Detect Scheduled Tasks Created to run at LOGON**   | This rule detects scheduled tasks created to run at logon, a common persistence mechanism used by attackers.
Disable Edge Phishing Filter**   | This rule disables the Edge phishing filter, a feature that attackers might try to bypass to execute phishing attacks.
Disable Event Logging with wevtutil**   | Monitors for commands attempting to disable event logging using wevtutil, which can be used to hide malicious activities by disabling logs.
Disable of LocalAccountTokenFilterPolicy**   | Monitors for commands attempting to disable LocalAccountTokenFilterPolicy, which can allow remote administrative connections without UAC restrictions.
Disable SmartScreen - Edge**   | This rule disables SmartScreen for Edge, ensuring that attempts to bypass this browser security feature are blocked.
Disable SmartScreen - Windows**   | This rule disables SmartScreen for Windows, which can be a target for attackers trying to bypass this security feature.
Disable Windows Firewall via Command Line**   | This rule disables the Windows firewall via command line, a common tactic used by attackers to disable security defenses.
Disable Windows IIS HTTP Logging**   | Monitors for commands attempting to disable Windows IIS HTTP logging using appcmd, which can be used to hide malicious web activities.
DNS Exfiltration and Tunneling Tools Execution**   | Monitors for command lines indicating the execution of DNS exfiltration and tunneling tools such as ionide.exe and dnscat2, which may be used for data exfiltration and covert communication.
DNS ServerLevelPluginDll Install**   | Monitors for command lines indicating the installation of a DNS ServerLevelPluginDll using dnscmd, which may be used to establish persistence on a system.
Dropping Of Password Filter DLL**   | Monitors for command lines indicating the addition of a password filter DLL to the LSA registry key, which may be used to establish persistence on a system.
DumpStack.log Defender Evasion**   | Monitors for command lines indicating the use of the DumpStack.log file to evade Windows Defender, which may be used to hide malicious activities.
Execute LOLBIN - rundll32.exe advpack.dll,RegisterOCX**   | This rule blocks the execution of LOLBIN rundll32.exe with advpack.dll and RegisterOCX, preventing misuse of these binaries for unauthorized actions.
Execute LOLBIN - rundll32.exe pcwutl.dll,LaunchApplication**   | This rule detects and blocks the execution of LOLBIN rundll32.exe with pcwutl.dll and LaunchApplication, preventing potential exploitation of these binaries for unauthorized actions.
Execute LOLBIN - rundll32.exe url.dll,FileProtocolHandler**   | This rule detects and blocks the execution of LOLBIN (Living Off The Land Binary) rundll32.exe with url.dll or FileProtocolHandler, preventing misuse of these legitimate binaries for malicious purposes.
Execute LOLBIN - rundll32.exe url.dll,OpenURLA**   | This rule blocks the execution of LOLBIN rundll32.exe with url.dll and OpenURL, preventing misuse of these binaries for malicious activities.
Execute LOLBIN - rundll32.exe zipfldr.dll,RouteTheCall**   | This rule blocks the execution of LOLBIN rundll32.exe with zipfldr.dll and RouteTheCall, preventing misuse of these binaries for malicious purposes.
Execution via CL_Invocation**   | Monitors for command lines indicating execution via CL_Invocation with SyncInvoke, which may be used for malicious script execution.
F-Secure C3 Load by Rundll32**   | Monitors for command lines indicating the use of rundll32.exe to load F-Secure C3 using the StartNodeRelay function, which may indicate malicious activity.
Hidden Powershell in Link File Pattern**   | Monitors for command lines indicating hidden PowerShell execution via link (.lnk) files, excluding specific legitimate patterns.
Impacket Heuristic Detections**   | This rule uses heuristic analysis to detect the use of Impacket, a collection of Python classes for working with network protocols, often used by attackers for lateral movement and credential dumping.
Impair Windows Audit Log Policy**   | Monitors for commands attempting to impair Windows audit log policy settings, which can disable logging of important security events.
Inject PowerShell Cradle CommandLine Flags**   | Monitors for command lines indicating the injection of PowerShell cradle command line flags, excluding specific legitimate patterns.
Malicious Named Pipes Detected**   | Monitors for commands indicating the use of malicious named pipes, which may be used for inter-process communication by malicious software.
Microsoft Teams Updater Living off the Land 2**   | This rule blocks attempts to update layers of Windows through command line, preventing unauthorized modifications.
Mimikatz Heuristic Detections**   | This rule uses heuristic analysis to detect the presence and execution of Mimikatz, a tool commonly used to extract passwords and other sensitive information from memory.
Moses Staff Campaign**   | Monitors for command lines indicating activity related to the Moses Staff Campaign, particularly involving Firefox Default Browser Agent and a specific identifier.
nps.exe (not powershell) Detection**   | Monitors for commands indicating the use of nps.exe, which is commonly associated with malicious activities.
Possible Attempt to Delete schtasks Security Descriptor**   | Monitors for commands indicating possible attempts to delete scheduled task security descriptors, which may be used to hide or modify scheduled tasks.
Possible Powershell Downgrade Attack**   | Monitors for commands indicating possible attempts to perform a PowerShell downgrade attack by specifying an older version.
Possible use of Hashcat HackTool**   | Monitors for Hash cracking using Hashcat tool. Hash cracking allows attackers to collect passwords and use them later on as part of their operation.
Possibly Malicious Usage of Certutil**   | Monitors for command lines indicating potentially malicious use of certutil with the urlcache and -f flags, which may be used for data transfer or exfiltration.
Possibly Suspicious Regsvc Registry Modification**   | Monitors for commands indicating modifications to the Regsvc registry keys, which may be used to establish persistence or alter system services.
PowerShell Advanced WebClient and DownloadString**   | This rule detects and blocks the use of PowerShell obfuscation to replace inline in functional call, a technique used to hide malicious commands.
PowerShell Code Obfuscation Replace Inline in Function Call**   | This rule detects and blocks the use of PowerShell obfuscation bypass in functional call, which can be used to evade detection.
PowerShell Domain Enumeration**   | Monitors for PowerShell commands used for domain enumeration activities, such as get-adgroupmember, get-domainuser, Get-ADTrust, Get-AppLockerPolicy, Get-DomainObjectAcl, and Get-DomainOU.
Powershell Execution Bypass Detected**   | Monitors for commands indicating the use of PowerShell with the execution policy set to bypass, excluding specific legitimate patterns.
PowerShell Inline Alternative Execution Bypass**   | This rule detects and blocks alternative execution methods within PowerShell scripts, which can be used to bypass security controls.
PowerShell Inline Process Enumerate and Terminate Command-Line**   | This rule detects and blocks the use of PowerShell inline process enumeration and termination command-line sequences, which can be used to manipulate running processes.
Powershell Net.WebClient Detected**   | Monitors for commands indicating the use of PowerShell's Net.WebClient, which can be used to download or upload data, potentially indicating malicious activity.
PowerShell String Concatenation Bypass in Function Call**   | This rule detects and blocks the use of PowerShell string concatenation in function calls, a technique often used to obfuscate malicious code.
Snatch Ransomware**   | Monitors for command lines indicating the execution of Snatch ransomware, specifically looking for shutdown commands with immediate restart and stopping of the SuperBackupMan service.
Suspicious 7zip Subprocess**   | Monitors for suspicious subprocesses of 7zip, specifically when 7zfm launches cmd.exe or vice versa, which may indicate attempts to evade detection or delete evidence.
Suspicious MS Office Child Process**   | Monitors for suspicious child processes spawned by MS Office applications.
SysInternals Junction.exe Symbolic Link Tool**   | This rule detects the use of Sysinternals junction.exe with symbolic link tools, which can be used for lateral movement or privilege escalation.
Usage of 'Get-ADUser' Users Enumeration**   | Monitors for commands using Get-ADUser, which can indicate user enumeration activity in Active Directory environments.
Usage of 'Set-NetFirewallProfile' to Disable FW**   | Monitors for commands using Set-NetFirewallProfile to disable the firewall, which may indicate an attempt to reduce the system's security posture.
Wbadmin Delete Systemstatebackup**   | Monitors for command lines indicating the deletion of system state backups using wbadmin with the -keepVersions:0 flag, which may indicate an attempt to destroy backup data.
WDigest Usage to Store ClearText Creds via Registry**   | Monitors for commands modifying the WDigest registry settings to enable the storage of cleartext credentials, which can indicate credential theft activity.
Windows Crypto Mining Indicators**   | Monitors for command lines indicating potential crypto mining activities, such as specific flags and parameters used by mining software, including pool connections and donation levels.
WinRM Command-Line WMI Process Creation**   | This rule detects the creation of processes via Windows Remote Management (WinRM) using WMI, a technique often used for remote code execution and lateral movement.

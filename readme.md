| **Rule Name** | **Description** |
|--------------|---------------|
| **Abusing Windows Telemetry For Persistence** | Monitors for commands abusing Windows Telemetry tasks, such as Microsoft Compatibility Appraiser, for persistence, excluding specific legitimate patterns. |
| **Access of Stored Browser Credentials** | Monitors process command line for access to stored browser credentials. |
| **Active Directory Attack via PowerShell Exploit** | Monitors for PowerShell commands targeting Active Directory vulnerabilities or sensitive data, indicating potential exploitation. |
| **ADCSPwn Hack Tool** | Monitors for the use of ADCSPwn hack tool, which exploits Active Directory Certificate Services vulnerabilities, using specific command line patterns. |
| **Admins Group Enumeration** | Monitors for command lines attempting to enumerate the Admins group. |
| **AnyDesk Silent Installation Detected** | Monitors for silent installation of AnyDesk using specific command line patterns, which may indicate unauthorized remote access setup. |
| **Apostle Ransomware using OrcusRAT** | Detection of potentially malicious activity related to DNS ServerLevelPluginDll Install. |
| **Atomic #1 - Indirect Command Execution - pcalua.exe** | Monitors for indirect command execution using pcalua.exe -a. |
| **Atomic #22 - Disable UAC AdminPromptBehavior By RegKey** | Monitors for commands attempting to disable UAC AdminPromptBehavior by modifying the registry key. |
| **Atomic Test #2 - Detect Virtualization Environment** | Monitors for commands attempting to detect a virtualization environment by querying thermal zone temperature. |
| **Atomic Test #3 - Bypass UAC using Fodhelper** | Monitors for commands attempting to bypass UAC using Fodhelper by modifying the registry key. |
| **Atomic Test #7 - Bypass UAC using sdclt DelegateExecute** | Monitors for commands attempting to bypass UAC using sdclt DelegateExecute by modifying the registry key. |
| **Atomic Test #8 - Disable UAC using reg.exe** | Monitors for commands attempting to disable UAC using reg.exe by modifying the registry key. |
| **Base64 Encoded Listing of Shadowcopy** | Detection of potentially malicious activity related to DNS Exfiltration and Tunneling Tools Execution. |
| **BazarLoader dumps AD info** | Monitors for command lines indicating the dumping of Active Directory information by BazarLoader, which targets files like pwddump.txt and users.csv. |
| **Bitsadmin Usage Detected** | Monitors for usage of bitsadmin command, which can be used for malicious purposes. |
| **BlackByte Ransomware** | Monitors for command lines indicative of BlackByte Ransomware activities. |
| **Block desktopimgdownldr LOLBin** | This rule blocks the download of LOLBIN using the desktopimgdownldr utility, preventing misuse of this legitimate binary. |
| **Block LOLBIN certutil.exe -decode** | This rule blocks the use of LOLBIN certutil.exe with the -decode flag, which can be used to decode malicious payloads. |
| **Block MSBuild on User Endpoints** | This rule blocks the use of MSBuild on user endpoints, a technique that can be used by attackers to compile and execute malicious code. |
| **Block Office from executing Alternative PowerShell** | This rule prevents Office applications from executing alternative PowerShell scripts, which can be used to bypass traditional security controls. |
| **Block PowerShell from Changing WindowsDefender Settings** | This rule blocks PowerShell from changing Windows Defender settings, preventing potential tampering with security configurations. |
| **Block PowerShell Invoke-Web-Request via Inline Command-Line** | This rule detects and blocks the use of PowerShell invoke-web-request with inline command-line, a technique used to download malicious payloads. |
| **Block Reg Add Disabling Windows Defender** | This rule detects and blocks the use of PowerShell advanced WebClient and download string, which can be used to download malicious files. |
| **Block Setting Image File Execution Debugger** | This rule prevents the setting of the Image File Execution Debugger, a technique used by attackers to intercept and manipulate the execution of processes. |
| **Block Windows Defender DownloadFile LOLBin** | This rule blocks Windows Defender from downloading LOLBIN, preventing potential bypass of security measures using trusted binaries. |
| **Boot Values Being Potentially Edited** | Monitors for commands that may indicate boot values are being edited. |
| **Clear Windows Audit Policy Config** | Monitors for commands attempting to clear Windows audit policy configuration. |
| **CobaltStrike Load by Rundll32** | Monitors for command lines indicating the use of rundll32.exe to load CobaltStrike, which may indicate malicious activity leveraging the StartW function in DLL files. |
| **COMPlus_ETWEnabled Command Line Arguments** | Monitors for command lines setting COMPlus_ETWEnabled to 0, which may indicate attempts to disable Event Tracing for Windows (ETW) for evasion purposes. |
| **Copying Sensitive Files with Credential Data** | Monitors for command lines using esentutl.exe to copy sensitive files containing credential data, which may indicate credential dumping activities. |
| **Creation of Named Pipe Detected** | Monitors for commands indicating the creation of named pipes. |
| **CVE-2021-26857 Exchange Exploitation** | Monitors for the exploitation of CVE-2021-26857 in Exchange Server by checking for MWorkerProcess.exe activity, excluding specific legitimate patterns. |
| **Detect and Block PowerSharpPack PowerShell Scripts** | This rule detects and blocks the execution of PowerSharpPack PowerShell scripts, a toolkit used for post-exploitation activities. |
| **Detect CMD Echoing DOTNET Code into a File** | This rule blocks the use of CMD to echo .NET code into files, a technique used to create and execute malicious .NET applications. |
| **Detect Creation of Symbolic Links** | This rule detects the creation of symbolic links, which can be used by attackers to bypass file system restrictions and access unauthorized files. |
| **Detect Generic Reg Add RunOnce** | This rule detects the use of generic registry add RunOnce commands, which can be used by malware to achieve persistence. |
| **Detect Scheduled Tasks Created to run at LOGON** | This rule detects scheduled tasks created to run at logon, a common persistence mechanism used by attackers. |

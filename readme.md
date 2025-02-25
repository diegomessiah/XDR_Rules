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

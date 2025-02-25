rule:
  name: "WinRM Command-Line WMI Process Creation"
  description: "Detects process creation via WinRM using WMI commands, which may indicate lateral movement or remote code execution."
  platform: "windows"
  condition: "process_creation"
  indicators:
    - field: "ProcessImagePath"
      contains:
        - "\\wmic.exe"
        - "\\powershell.exe"
    - field: "ProcessCommandLine"
      regex:
        - "(?i)wmic\s+/node:.*\s+process\s+call\s+create.*"
        - "(?i)powershell\s+-command\s+.*Invoke-WmiMethod.*"
  response:
    action: "alert"
    severity: "high"
    tags:
      - "winrm"
      - "wmi"
      - "lateral_movement"
      - "remote_execution"
  metadata:
    author: "Security Team"
    created: "2025-02-25"
    category: "Threat Detection"
    mitre_attack:
      - T1028  # Windows Remote Management (WinRM)
      - T1047  # WMI Execution

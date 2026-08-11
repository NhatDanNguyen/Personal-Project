rule Suspicious_PowerShell
{
    meta:
        description = "Detects PowerShell references"
        severity = "medium"

    strings:
        $powershell = "powershell" nocase
        $powershell_exe = "powershell.exe" nocase
        $encoded = "-enc" nocase
        $encoded_command = "-encodedcommand" nocase

    condition:
        1 of them
}


rule Suspicious_Command_Execution
{
    meta:
        description = "Detects common command execution utilities"
        severity = "medium"

    strings:
        $cmd = "cmd.exe" nocase
        $wscript = "wscript.exe" nocase
        $cscript = "cscript.exe" nocase
        $mshta = "mshta.exe" nocase
        $rundll32 = "rundll32.exe" nocase

    condition:
        1 of them
}


rule Suspicious_Process_Injection
{
    meta:
        description = "Detects APIs commonly associated with process injection"
        severity = "high"

    strings:
        $virtualalloc = "VirtualAllocEx" nocase
        $writeprocess = "WriteProcessMemory" nocase
        $remotethread = "CreateRemoteThread" nocase

    condition:
        2 of them
}


rule Suspicious_Network_Activity
{
    meta:
        description = "Detects common network communication indicators"
        severity = "medium"

    strings:
        $http = "http://" nocase
        $https = "https://" nocase
        $internetopen = "InternetOpen" nocase
        $internetconnect = "InternetConnect" nocase
        $winhttp = "WinHttp" nocase

    condition:
        1 of them
}
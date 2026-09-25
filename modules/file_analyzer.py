import hashlib
import os
import pefile
import re


def calculate_hashes(file_path):

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            chunk = file.read(4096)

            if not chunk:
                break

            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest()
    }


def get_file_information(file_path):

    return {
        "filename": os.path.basename(file_path),
        "size": os.path.getsize(file_path),
        "path": os.path.abspath(file_path)
    }


def analyze_pe(file_path):

    try:

        pe = pefile.PE(file_path)

    except pefile.PEFormatError:

        return {
            "is_pe": False,
            "error": "Not a valid PE file"
        }

    # ==========================
    # Architecture
    # ==========================

    if pe.FILE_HEADER.Machine == 0x14c:

        architecture = "x86 (32-bit)"

    elif pe.FILE_HEADER.Machine == 0x8664:

        architecture = "x64 (64-bit)"

    else:

        architecture = "Unknown"


    # ==========================
    # Entry Point
    # ==========================

    entry_point = hex(
        pe.OPTIONAL_HEADER.AddressOfEntryPoint
    )


    # ==========================
    # Image Base
    # ==========================

    image_base = hex(
        pe.OPTIONAL_HEADER.ImageBase
    )


    # ==========================
    # Sections
    # ==========================

    sections = []

    for section in pe.sections:

        name = (
            section.Name
            .decode(errors="ignore")
            .rstrip("\x00")
        )

        sections.append({

            "name": name,

            "virtual_address":
                hex(section.VirtualAddress),

            "virtual_size":
                section.Misc_VirtualSize,

            "raw_size":
                section.SizeOfRawData,

            "entropy":
                round(
                    section.get_entropy(),
                    2
                )

        })


    # ==========================
    # Compile Timestamp
    # ==========================

    timestamp = (
        pe.FILE_HEADER.TimeDateStamp
    )


    return {

        "is_pe": True,

        "architecture":
            architecture,

        "entry_point":
            entry_point,

        "image_base":
            image_base,

        "compile_timestamp":
            timestamp,

        "sections":
            sections

    }

def analyze_imports(file_path):

    try:

        pe = pefile.PE(file_path)

    except pefile.PEFormatError:

        return {
            "success": False,
            "error": "Not a valid PE file",
            "imports": []
        }


    imports = []


    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):

        return {
            "success": True,
            "imports": []
        }


    for entry in pe.DIRECTORY_ENTRY_IMPORT:

        try:

            dll_name = entry.dll.decode(
                errors="ignore"
            )

        except AttributeError:

            dll_name = str(entry.dll)


        functions = []


        for imported_function in entry.imports:

            if imported_function.name:

                try:

                    function_name = (
                        imported_function.name
                        .decode(errors="ignore")
                    )

                except AttributeError:

                    function_name = str(
                        imported_function.name
                    )

            else:

                function_name = (
                    f"Ordinal_{imported_function.ordinal}"
                )


            functions.append(
                function_name
            )


        imports.append({

            "dll": dll_name,

            "functions": functions

        })


    return {

        "success": True,

        "imports": imports

    }

SUSPICIOUS_APIS = {

    # ========================================================
    # PROCESS INJECTION
    # ========================================================
    "Process Injection": {
        "important": [
            "WriteProcessMemory",
            "CreateRemoteThread",
            "CreateRemoteThreadEx",
            "QueueUserAPC",
            "SetThreadContext",
            "NtWriteVirtualMemory",
            "NtMapViewOfSection"
        ],

        "supporting": [
            "VirtualAllocEx",
            "VirtualProtectEx",
            "OpenProcess",
            "GetThreadContext",
            "NtUnmapViewOfSection"
        ]
    },

    # ========================================================
    # PROCESS MANIPULATION
    # ========================================================
    "Process Manipulation": {
        "important": [
            "TerminateProcess",
            "SuspendThread",
            "ResumeThread",
            "DebugActiveProcess"
        ],

        "supporting": [
            "OpenProcess",
            "OpenThread",
            "GetProcessId",
            "GetExitCodeProcess",
            "DebugActiveProcessStop"
        ]
    },

    # ========================================================
    # PROCESS CREATION
    # ========================================================
    "Process Creation": {
        "important": [
            "CreateProcessAsUserA",
            "CreateProcessAsUserW",
            "CreateProcessWithTokenW",
            "CreateProcessWithLogonW"
        ],

        "supporting": [
            "CreateProcessA",
            "CreateProcessW"
        ]
    },

    # ========================================================
    # PERSISTENCE
    # ========================================================
    "Persistence": {
        "important": [
            "RegSetValueExA",
            "RegSetValueExW",
            "CreateServiceA",
            "CreateServiceW",
            "StartServiceA",
            "StartServiceW"
        ],

        "supporting": [
            "RegCreateKeyA",
            "RegCreateKeyW",
            "RegCreateKeyExA",
            "RegCreateKeyExW",
            "RegOpenKeyA",
            "RegOpenKeyW",
            "RegOpenKeyExA",
            "RegOpenKeyExW",
            "RegSetValueA",
            "RegSetValueW",
            "OpenSCManagerA",
            "OpenSCManagerW"
        ]
    },

    # ========================================================
    # NETWORK COMMUNICATION
    # ========================================================
    "Network Communication": {
        "important": [
            "InternetConnectA",
            "InternetConnectW",
            "InternetOpenUrlA",
            "InternetOpenUrlW",
            "HttpOpenRequestA",
            "HttpOpenRequestW",
            "HttpSendRequestA",
            "HttpSendRequestW",
            "WinHttpConnect",
            "WinHttpOpenRequest",
            "WinHttpSendRequest",
            "connect",
            "send",
            "recv",
            "sendto",
            "recvfrom"
        ],

        "supporting": [
            "InternetOpenA",
            "InternetOpenW",
            "WinHttpOpen",
            "WinHttpReceiveResponse",
            "WSAStartup",
            "socket"
        ]
    },

    # ========================================================
    # FILE OPERATIONS
    # ========================================================
    "File Operations": {
        "important": [
            "DeleteFileA",
            "DeleteFileW",
            "MoveFileA",
            "MoveFileW",
            "SetFileAttributesA",
            "SetFileAttributesW"
        ],

        "supporting": [
            "CreateFileA",
            "CreateFileW",
            "ReadFile",
            "WriteFile",
            "CopyFileA",
            "CopyFileW",
            "GetFileAttributesA",
            "GetFileAttributesW",
            "GetTempPathA",
            "GetTempPathW",
            "GetTempFileNameA",
            "GetTempFileNameW"
        ]
    },

    # ========================================================
    # COMMAND / SHELL EXECUTION
    # ========================================================
    "Command / Shell Execution": {
        "important": [
            "WinExec",
            "ShellExecuteA",
            "ShellExecuteW",
            "ShellExecuteExA",
            "ShellExecuteExW",
            "system",
            "_wsystem",
            "popen",
            "_popen",
            "_wpopen"
        ],

        "supporting": [
            "CreateProcessA",
            "CreateProcessW"
        ]
    },

    # ========================================================
    # KEYBOARD / INPUT CAPTURE
    # ========================================================
    "Keyboard Input Capture": {
        "important": [
            "GetAsyncKeyState",
            "GetKeyState",
            "GetKeyboardState",
            "GetRawInputData",
            "GetRawInputBuffer",
            "RegisterRawInputDevices"
        ],

        "supporting": [
            "GetKeyboardLayout",
            "GetKeyboardLayoutList",
            "GetKeyNameTextA",
            "GetKeyNameTextW",
            "GetRawInputDeviceInfoA",
            "GetRawInputDeviceInfoW",
            "GetRawInputDeviceList"
        ]
    },

    # ========================================================
    # CREDENTIAL / TOKEN ACCESS
    # ========================================================
    "Credential / Token Access": {
        "important": [
            "DuplicateTokenEx",
            "AdjustTokenPrivileges",
            "ImpersonateLoggedOnUser",
            "ImpersonateToken",
            "LogonUserA",
            "LogonUserW"
        ],

        "supporting": [
            "OpenProcessToken",
            "OpenThreadToken",
            "GetTokenInformation",
            "DuplicateToken",
            "LookupPrivilegeValueA",
            "LookupPrivilegeValueW",
            "RevertToSelf"
        ]
    },

    # ========================================================
    # SYSTEM INFORMATION
    # ========================================================
    "System Information": {
        "important": [],

        "supporting": [
            "GetComputerNameA",
            "GetComputerNameW",
            "GetUserNameA",
            "GetUserNameW",
            "GetVersionExA",
            "GetVersionExW",
            "GetSystemInfo",
            "GetNativeSystemInfo",
            "GlobalMemoryStatusEx",
            "GetPhysicallyInstalledSystemMemory",
            "GetLogicalDrives",
            "GetLogicalDriveStringsA",
            "GetLogicalDriveStringsW",
            "GetDiskFreeSpaceA",
            "GetDiskFreeSpaceW",
            "GetDiskFreeSpaceExA",
            "GetDiskFreeSpaceExW",
            "GetAdaptersInfo",
            "GetAdaptersAddresses",
            "GetCurrentProcessId",
            "GetCurrentThreadId"
        ]
    },

    # ========================================================
    # SECURITY / DEBUGGING
    # ========================================================
    "Security / Debugging": {
        "important": [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "DebugActiveProcess"
        ],

        "supporting": [
            "OutputDebugStringA",
            "OutputDebugStringW",
            "DebugActiveProcessStop",
            "CheckTokenMembership",
            "GetSecurityInfo",
            "SetSecurityInfo"
        ]
    }
}


def detect_suspicious_apis(import_info):

    findings = []


    if not import_info["success"]:

        return findings


    imported_functions = set()


    for dll in import_info["imports"]:

        for function in dll["functions"]:

            imported_functions.add(
                function
            )


    for category, importance, api_list in SUSPICIOUS_APIS.items():

        matches = []


        for api in api_list:

            if api in imported_functions:

                matches.append(api)


        if matches:

            findings.append({

                "category": category,
                "importance": importance,
                "apis": matches

            })


    return findings

def extract_strings(file_path, minimum_length=4):

    with open(file_path, "rb") as file:

        data = file.read()


    # Extract ASCII strings

    pattern = rb"[\x20-\x7E]{%d,}" % minimum_length

    matches = re.findall(
        pattern,
        data
    )


    strings = []

    for match in matches:

        try:

            strings.append(
                match.decode(
                    "ascii",
                    errors="ignore"
                )
            )

        except Exception:

            continue


    return strings

def extract_iocs(strings):

    iocs = {

        "urls": [],
        "ip_addresses": [],
        "emails": [],
        "file_paths": [],
        "registry_paths": [],
        "powershell": [],
        "commands": []

    }


    # ==========================
    # Regular Expressions
    # ==========================

    url_pattern = re.compile(
        r"https?://[^\s\"'<>]+",
        re.IGNORECASE
    )


    ip_pattern = re.compile(
        r"\b(?:"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|"
        r"[1-9]?\d)\."
        r"){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|"
        r"[1-9]?\d)\b"
    )


    email_pattern = re.compile(
        r"\b[A-Za-z0-9._%+-]+@"
        r"[A-Za-z0-9.-]+\."
        r"[A-Za-z]{2,}\b"
    )


    file_path_pattern = re.compile(
        r"[A-Za-z]:\\[^\"'\r\n]+"
    )


    registry_pattern = re.compile(
        r"(?:HKLM|HKCU|HKCR|HKU|HKCC)"
        r"\\[^\"'\r\n]+",
        re.IGNORECASE
    )


    for string in strings:

        # ==========================
        # URLs
        # ==========================

        urls = url_pattern.findall(
            string
        )

        for url in urls:

            if url not in iocs["urls"]:

                iocs["urls"].append(url)


        # ==========================
        # IP Addresses
        # ==========================

        ips = ip_pattern.findall(
            string
        )

        for ip in ips:

            if ip not in iocs["ip_addresses"]:

                iocs["ip_addresses"].append(ip)


        # ==========================
        # Emails
        # ==========================

        emails = email_pattern.findall(
            string
        )

        for email in emails:

            if email not in iocs["emails"]:

                iocs["emails"].append(email)


        # ==========================
        # File Paths
        # ==========================

        paths = file_path_pattern.findall(
            string
        )

        for path in paths:

            if path not in iocs["file_paths"]:

                iocs["file_paths"].append(path)


        # ==========================
        # Registry
        # ==========================

        registry_paths = registry_pattern.findall(
            string
        )

        for registry in registry_paths:

            if registry not in iocs["registry_paths"]:

                iocs["registry_paths"].append(
                    registry
                )


        # ==========================
        # PowerShell
        # ==========================

        if "powershell" in string.lower():

            if string not in iocs["powershell"]:

                iocs["powershell"].append(
                    string
                )


        # ==========================
        # Commands
        # ==========================

        command_names = [

            "cmd.exe",
            "powershell.exe",
            "wscript.exe",
            "cscript.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "mshta.exe"

        ]


        for command in command_names:

            if command.lower() in string.lower():

                if string not in iocs["commands"]:

                    iocs["commands"].append(
                        string
                    )


    return iocs
def analyze_entropy(pe_info):

    findings = []

    if not pe_info.get("is_pe", False):
        return findings

    for section in pe_info["sections"]:

        entropy = section["entropy"]

        if entropy >= 7.5:

            findings.append({
                "section": section["name"],
                "entropy": entropy,
                "severity": "HIGH",
                "message": "Very high entropy. Possible packing or encryption."
            })

        elif entropy >= 6.5:

            findings.append({
                "section": section["name"],
                "entropy": entropy,
                "severity": "MEDIUM",
                "message": "High entropy. Section may contain compressed or encrypted data."
            })

    return findings

def calculate_risk_score(
    suspicious_api_findings,
    entropy_findings,
    iocs,
    yara_findings=None
):
    IMPORTANT_POINTS = {
        "Process Injection": 15,
        "Process Manipulation": 3,
        "Process Creation": 3,
        "Persistence": 10,
        "Network Communication": 3,
        "File Operations": 1,
        "Command / Shell Execution": 5,
        "Keyboard Input Capture": 8,
        "Credential / Token Access": 8,
        "System Information": 0,
        "Security / Debugging": 3
    }

    SUPPORTING_POINTS = {
        "Process Injection": 5,
        "Process Manipulation": 1,
        "Process Creation": 1,
        "Persistence": 3,
        "Network Communication": 1,
        "File Operations": 0,
        "Command / Shell Execution": 1,
        "Keyboard Input Capture": 2,
        "Credential / Token Access": 2,
        "System Information": 0,
        "Security / Debugging": 1
    }
    SEVERITY = {
        "Process Injection": "CRITICAL",
        "Process Manipulation": "LOW",
        "Process Creation": "LOW",
        "Persistence": "HIGH",
        "Network Communication": "LOW",
        "File Operations": "VERY LOW",
        "Command / Shell Execution": "MEDIUM",
        "Keyboard Input Capture": "HIGH",
        "Credential / Token Access": "HIGH",
        "System Information": "INFO",
        "Security / Debugging": "LOW"
    }
    score = 0

    indicators = []


    # ========================================================
    # SUSPICIOUS APIs
    # ========================================================

    for finding in suspicious_api_findings:

        category = finding["category"]
        importance = finding["severity"]
        apis = finding["apis"]

        if importance == "important":
            points = IMPORTANT_POINTS.get(category, 0)
        else:
            points = SUPPORTING_POINTS.get(category, 0)

            severity = SEVERITY.get(category, "INFO")

            score += points

            indicators.append({
                "severity": severity,
                "importance": importance,
                "points": points,
                "message": f"{category}: {', '.join(apis)}"
            })


    # ========================================================
    # ENTROPY
    # ========================================================
    entropy_points = 0
    for finding in entropy_findings:

        if finding["severity"] == "HIGH":
            points = 5
            entropy_points += points

        else:
            points = 3
            entropy_points += points



        indicators.append({

            "severity": finding["severity"],

            "points": points,

            "message": finding["message"]

        })
    score += min(entropy_points, 10)

    # ========================================================
    # URLS
    # ========================================================

    if iocs.get("urls"):

        points = min(
            len(iocs["urls"]),
            5
        )


        score += points


        indicators.append({

            "severity": "MEDIUM",

            "points": points,

            "message": (
                f"{len(iocs['urls'])} "
                f"URL(s) detected"
            )

        })


    # ========================================================
    # IP ADDRESSES
    # ========================================================

    if iocs.get("ip_addresses"):

        points = min(
            len(iocs["ip_addresses"]),
            5
        )


        score += points


        indicators.append({

            "severity": "MEDIUM",

            "points": points,

            "message": (
                f"{len(iocs['ip_addresses'])} "
                f"IP address(es) detected"
            )

        })


    # ========================================================
    # POWERSHELL
    # ========================================================

    if iocs.get("powershell"):

        points = 4


        score += points


        indicators.append({

            "severity": "LOW",

            "points": points,

            "message":
                "PowerShell reference detected"

        })


    # ========================================================
    # COMMANDS
    # ========================================================

    if iocs.get("commands"):

        points = 2


        score += points


        indicators.append({

            "severity": "LOW",

            "points": points,

            "message":
                "Suspicious command reference detected"

        })


    # ========================================================
    # YARA FINDINGS
    # ========================================================

    if yara_findings:

        for finding in yara_findings:

            severity = finding.get(
                "severity",
                "MEDIUM"
            ).upper()


            # -----------------------------------------------
            # YARA SCORE
            # -----------------------------------------------

            if severity == "CRITICAL":

                points = 15


            elif severity == "HIGH":

                points = 10


            elif severity == "MEDIUM":

                points = 5


            elif severity == "LOW":

                points = 2


            else:

                points = 2

            score += points

            # -----------------------------------------------
            # YARA INDICATOR
            # -----------------------------------------------

            indicators.append({

                "severity": severity,

                "points": points,

                "message": (
                    f"YARA rule matched: "
                    f"{finding['rule']}"
                )

            })


    # ========================================================
    # CAP SCORE
    # ========================================================

    score = min(
        score,
        100
    )


    # ========================================================
    # RISK LEVEL
    # ========================================================

    if score >= 85:

        risk_level = "CRITICAL"


    elif score >= 70:

        risk_level = "HIGH"


    elif score >= 40:

        risk_level = "MEDIUM"


    else:

        risk_level = "LOW"


    # ========================================================
    # RETURN RESULT
    # ========================================================

    return {

        "score": score,

        "level": risk_level,

        "indicators": indicators

    }
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

    "Process Injection": [

        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "OpenProcess"

    ],

    "Process Manipulation": [

        "CreateProcessA",
        "CreateProcessW",
        "OpenProcess",
        "TerminateProcess"

    ],

    "Persistence": [

        "RegCreateKeyExA",
        "RegCreateKeyExW",
        "RegSetValueExA",
        "RegSetValueExW"

    ],

    "Network Communication": [

        "InternetOpenA",
        "InternetOpenW",
        "InternetConnectA",
        "InternetConnectW",
        "HttpOpenRequestA",
        "HttpOpenRequestW",
        "WinHttpOpen",
        "WinHttpConnect"

    ],

    "File Operations": [

        "CreateFileA",
        "CreateFileW",
        "WriteFile",
        "DeleteFileA",
        "DeleteFileW"

    ],

    "Command Execution": [

        "WinExec",
        "ShellExecuteA",
        "ShellExecuteW",
        "CreateProcessA",
        "CreateProcessW"

    ]

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


    for category, api_list in SUSPICIOUS_APIS.items():

        matches = []


        for api in api_list:

            if api in imported_functions:

                matches.append(api)


        if matches:

            findings.append({

                "category": category,

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

    score = 0

    indicators = []


    # ========================================================
    # SUSPICIOUS APIs
    # ========================================================

    for finding in suspicious_api_findings:

        category = finding["category"]

        apis = finding["apis"]


        if category == "Process Injection":

            points = 30
            severity = "CRITICAL"


        elif category == "Persistence":

            points = 20
            severity = "HIGH"


        elif category == "Command Execution":

            points = 20
            severity = "HIGH"


        elif category == "Network Communication":

            points = 15
            severity = "HIGH"


        elif category == "Process Manipulation":

            points = 15
            severity = "HIGH"


        elif category == "File Operations":

            points = 5
            severity = "MEDIUM"


        else:

            points = 5
            severity = "LOW"


        score += points


        indicators.append({

            "severity": severity,

            "points": points,

            "message": (
                f"{category}: "
                f"{', '.join(apis)}"
            )

        })


    # ========================================================
    # ENTROPY
    # ========================================================

    for finding in entropy_findings:

        if finding["severity"] == "HIGH":

            points = 20

        else:

            points = 10


        score += points


        indicators.append({

            "severity": finding["severity"],

            "points": points,

            "message": finding["message"]

        })


    # ========================================================
    # URLS
    # ========================================================

    if iocs.get("urls"):

        points = min(
            len(iocs["urls"]) * 5,
            20
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
            len(iocs["ip_addresses"]) * 5,
            20
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

        points = 15


        score += points


        indicators.append({

            "severity": "HIGH",

            "points": points,

            "message":
                "PowerShell reference detected"

        })


    # ========================================================
    # COMMANDS
    # ========================================================

    if iocs.get("commands"):

        points = 10


        score += points


        indicators.append({

            "severity": "MEDIUM",

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

                points = 30


            elif severity == "HIGH":

                points = 20


            elif severity == "MEDIUM":

                points = 10


            elif severity == "LOW":

                points = 5


            else:

                points = 5


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
from modules.file_analyzer import calculate_risk_score


def empty_iocs():

    return {
        "urls": [],
        "ip_addresses": [],
        "powershell": [],
        "commands": []
    }


def test_no_indicators_is_low_risk():

    result = calculate_risk_score(
        [],
        [],
        empty_iocs(),
        []
    )

    assert result["score"] == 0
    assert result["level"] == "LOW"


def test_command_execution_adds_20_points():

    api_findings = [
        {
            "category": "Command Execution",
            "apis": ["CreateProcessW"]
        }
    ]

    result = calculate_risk_score(
        api_findings,
        [],
        empty_iocs(),
        []
    )

    assert result["score"] == 20
    assert result["level"] == "LOW"


def test_process_injection_adds_30_points():

    api_findings = [
        {
            "category": "Process Injection",
            "apis": ["VirtualAllocEx"]
        }
    ]

    result = calculate_risk_score(
        api_findings,
        [],
        empty_iocs(),
        []
    )

    assert result["score"] == 30
    assert result["level"] == "LOW"


def test_multiple_indicators_create_medium_risk():

    api_findings = [
        {
            "category": "Process Injection",
            "apis": ["VirtualAllocEx"]
        },
        {
            "category": "Command Execution",
            "apis": ["CreateProcessW"]
        }
    ]

    result = calculate_risk_score(
        api_findings,
        [],
        empty_iocs(),
        []
    )

    assert result["score"] == 50
    assert result["level"] == "MEDIUM"


def test_yara_high_severity_adds_20_points():

    yara_findings = [
        {
            "rule": "Test_Rule",
            "severity": "HIGH",
            "description": "Test rule",
            "matches": []
        }
    ]

    result = calculate_risk_score(
        [],
        [],
        empty_iocs(),
        yara_findings
    )

    assert result["score"] == 20


def test_yara_medium_severity_adds_10_points():

    yara_findings = [
        {
            "rule": "Test_Rule",
            "severity": "MEDIUM",
            "description": "Test rule",
            "matches": []
        }
    ]

    result = calculate_risk_score(
        [],
        [],
        empty_iocs(),
        yara_findings
    )

    assert result["score"] == 10


def test_url_increases_score():

    iocs = empty_iocs()

    iocs["urls"] = [
        "http://example.com"
    ]

    result = calculate_risk_score(
        [],
        [],
        iocs,
        []
    )

    assert result["score"] == 5


def test_ip_addresses_increase_score():

    iocs = empty_iocs()

    iocs["ip_addresses"] = [
        "192.168.1.10",
        "10.0.0.5"
    ]

    result = calculate_risk_score(
        [],
        [],
        iocs,
        []
    )

    assert result["score"] == 10


def test_powershell_increases_score():

    iocs = empty_iocs()

    iocs["powershell"] = [
        "powershell.exe"
    ]

    result = calculate_risk_score(
        [],
        [],
        iocs,
        []
    )

    assert result["score"] == 15


def test_score_never_exceeds_100():

    api_findings = [
        {
            "category": "Process Injection",
            "apis": ["VirtualAllocEx"]
        }
    ] * 10

    iocs = {
        "urls": ["http://example.com"] * 10,
        "ip_addresses": ["1.2.3.4"] * 10,
        "powershell": ["powershell.exe"],
        "commands": ["cmd.exe"]
    }

    yara_findings = [
        {
            "rule": "Test_Rule",
            "severity": "HIGH",
            "description": "Test rule",
            "matches": []
        }
    ] * 10

    result = calculate_risk_score(
        api_findings,
        [],
        iocs,
        yara_findings
    )

    assert result["score"] <= 100
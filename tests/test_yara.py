import os

from modules.yara_scanner import scan_file


TEST_FILE = os.path.join(
    "dist",
    "test_sample.exe"
)


def test_yara_returns_list():

    findings = scan_file(
        TEST_FILE
    )

    assert isinstance(
        findings,
        list
    )


def test_yara_findings_have_required_fields():

    findings = scan_file(
        TEST_FILE
    )

    for finding in findings:

        assert "rule" in finding
        assert "severity" in finding
        assert "description" in finding
        assert "matches" in finding
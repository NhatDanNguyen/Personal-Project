import os

from modules.analyzer import analyze_file


TEST_FILE = os.path.join(
    "dist",
    "test_sample.exe"
)


def test_complete_analysis():

    result = analyze_file(
        TEST_FILE
    )

    assert result is not None


def test_analysis_contains_file_info():

    result = analyze_file(
        TEST_FILE
    )

    assert "file_info" in result

    assert "filename" in result["file_info"]

    assert "size" in result["file_info"]


def test_analysis_contains_hashes():

    result = analyze_file(
        TEST_FILE
    )

    assert "hashes" in result

    assert "md5" in result["hashes"]

    assert "sha1" in result["hashes"]

    assert "sha256" in result["hashes"]


def test_analysis_contains_pe_information():

    result = analyze_file(
        TEST_FILE
    )

    assert "pe_info" in result

    assert "architecture" in result["pe_info"]

    assert "entry_point" in result["pe_info"]


def test_analysis_contains_import_information():

    result = analyze_file(
        TEST_FILE
    )

    assert "import_info" in result


def test_analysis_contains_api_findings():

    result = analyze_file(
        TEST_FILE
    )

    assert "api_findings" in result

    assert isinstance(
        result["api_findings"],
        list
    )


def test_analysis_contains_iocs():

    result = analyze_file(
        TEST_FILE
    )

    assert "iocs" in result


def test_analysis_contains_entropy():

    result = analyze_file(
        TEST_FILE
    )

    assert "entropy_findings" in result

    assert isinstance(
        result["entropy_findings"],
        list
    )


def test_analysis_contains_yara():

    result = analyze_file(
        TEST_FILE
    )

    assert "yara_findings" in result

    assert isinstance(
        result["yara_findings"],
        list
    )


def test_analysis_contains_risk():

    result = analyze_file(
        TEST_FILE
    )

    assert "risk" in result

    assert "score" in result["risk"]

    assert "level" in result["risk"]

    assert "indicators" in result["risk"]


def test_risk_score_is_valid():

    result = analyze_file(
        TEST_FILE
    )

    score = result["risk"]["score"]

    assert 0 <= score <= 100


def test_risk_level_is_valid():

    result = analyze_file(
        TEST_FILE
    )

    level = result["risk"]["level"]

    assert level in [
        "LOW",
        "MEDIUM",
        "HIGH"
    ]
import os

from modules.file_analyzer import analyze_pe


TEST_FILE = os.path.join(
    "dist",
    "test_sample.exe"
)


def test_pe_analysis_returns_result():

    result = analyze_pe(
        TEST_FILE
    )

    assert result is not None


def test_pe_architecture_exists():

    result = analyze_pe(
        TEST_FILE
    )

    assert "architecture" in result


def test_pe_entry_point_exists():

    result = analyze_pe(
        TEST_FILE
    )

    assert "entry_point" in result
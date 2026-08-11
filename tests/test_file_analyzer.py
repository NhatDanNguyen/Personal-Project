import os

from modules.file_analyzer import calculate_hashes


TEST_FILE = os.path.join(
    "dist",
    "test_sample.exe"
)


def test_sha256_exists():

    hashes = calculate_hashes(
        TEST_FILE
    )

    assert "sha256" in hashes


def test_sha256_length():

    hashes = calculate_hashes(
        TEST_FILE
    )

    assert len(
        hashes["sha256"]
    ) == 64


def test_sha1_length():

    hashes = calculate_hashes(
        TEST_FILE
    )

    assert len(
        hashes["sha1"]
    ) == 40


def test_md5_length():

    hashes = calculate_hashes(
        TEST_FILE
    )

    assert len(
        hashes["md5"]
    ) == 32
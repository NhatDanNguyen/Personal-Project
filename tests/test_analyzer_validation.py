import os
import pytest

from modules.analyzer import validate_sample


def test_missing_file():

    with pytest.raises(FileNotFoundError):

        validate_sample(
            "this_file_does_not_exist.exe"
        )


def test_empty_path():

    with pytest.raises(ValueError):

        validate_sample(
            ""
        )


def test_directory_is_rejected():

    with pytest.raises(ValueError):

        validate_sample(
            "."
        )


def test_valid_sample():

    test_file = os.path.join(
        "dist",
        "test_sample.exe"
    )

    assert validate_sample(
        test_file
    ) is True
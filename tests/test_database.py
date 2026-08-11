import modules.database as database


def setup_test_database(tmp_path, monkeypatch):

    test_database_dir = tmp_path / "database"

    test_database_path = (
        test_database_dir / "test_sandbox.db"
    )

    monkeypatch.setattr(
        database,
        "DATABASE_DIR",
        str(test_database_dir)
    )

    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        str(test_database_path)
    )


def test_database_initializes(
    tmp_path,
    monkeypatch
):

    setup_test_database(
        tmp_path,
        monkeypatch
    )

    database.initialize_database()

    assert (
        database.os.path.exists(
            database.DATABASE_PATH
        )
    )


def test_save_analysis(
    tmp_path,
    monkeypatch
):

    setup_test_database(
        tmp_path,
        monkeypatch
    )

    database.save_analysis(

        filename="test_sample.exe",

        sha256="TEST_SHA256_123",

        file_size=12345,

        risk_score=75,

        risk_level="HIGH",

        yara_matches=1,

        report_path="reports/test_report.txt"
    )

    result = database.find_by_sha256(
        "TEST_SHA256_123"
    )

    assert result is not None

    assert result[1] == "test_sample.exe"

    assert result[2] == "TEST_SHA256_123"

    assert result[3] == 12345

    assert result[5] == 75

    assert result[6] == "HIGH"

    assert result[7] == 1


def test_find_by_sha256(
    tmp_path,
    monkeypatch
):

    setup_test_database(
        tmp_path,
        monkeypatch
    )

    sha256 = "ABC123_TEST_HASH"

    database.save_analysis(

        filename="sample.exe",

        sha256=sha256,

        file_size=5000,

        risk_score=50,

        risk_level="MEDIUM",

        yara_matches=0,

        report_path="reports/sample.txt"
    )

    result = database.find_by_sha256(
        sha256
    )

    assert result is not None

    assert result[2] == sha256


def test_unknown_sha256_returns_none(
    tmp_path,
    monkeypatch
):

    setup_test_database(
        tmp_path,
        monkeypatch
    )

    result = database.find_by_sha256(
        "THIS_HASH_DOES_NOT_EXIST"
    )

    assert result is None


def test_analysis_history(
    tmp_path,
    monkeypatch
):

    setup_test_database(
        tmp_path,
        monkeypatch
    )

    database.save_analysis(

        filename="sample_one.exe",

        sha256="HASH_ONE",

        file_size=1000,

        risk_score=20,

        risk_level="LOW",

        yara_matches=0,

        report_path="reports/one.txt"
    )

    database.save_analysis(

        filename="sample_two.exe",

        sha256="HASH_TWO",

        file_size=2000,

        risk_score=80,

        risk_level="HIGH",

        yara_matches=2,

        report_path="reports/two.txt"
    )

    history = database.get_analysis_history()

    assert len(history) == 2

    assert history[0][1] == "sample_two.exe"

    assert history[1][1] == "sample_one.exe"


def test_duplicate_sha256_detection(
    tmp_path,
    monkeypatch
):

    setup_test_database(
        tmp_path,
        monkeypatch
    )

    sha256 = "DUPLICATE_TEST_HASH"

    database.save_analysis(

        filename="first_sample.exe",

        sha256=sha256,

        file_size=1000,

        risk_score=40,

        risk_level="MEDIUM",

        yara_matches=0,

        report_path="reports/first.txt"
    )

    existing = database.find_by_sha256(
        sha256
    )

    assert existing is not None

    assert existing[2] == sha256

    assert existing[1] == "first_sample.exe"
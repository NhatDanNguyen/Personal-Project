import sqlite3
import os
from datetime import datetime


# ==========================
# DATABASE PATH
# ==========================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATABASE_DIR = os.path.join(
    BASE_DIR,
    "database"
)

DATABASE_PATH = os.path.join(
    DATABASE_DIR,
    "sandbox.db"
)


# ==========================
# INITIALIZE DATABASE
# ==========================

def initialize_database():

    os.makedirs(
        DATABASE_DIR,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS analyses (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            filename TEXT NOT NULL,

            sha256 TEXT NOT NULL,

            file_size INTEGER,

            analysis_date TEXT,

            risk_score INTEGER,

            risk_level TEXT,

            yara_matches INTEGER,

            report_path TEXT

        )
        """
    )

    connection.commit()

    connection.close()


# ==========================
# SAVE ANALYSIS
# ==========================

def save_analysis(
    filename,
    sha256,
    file_size,
    risk_score,
    risk_level,
    yara_matches,
    report_path
):

    initialize_database()

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()

    analysis_date = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    cursor.execute(
        """
        INSERT INTO analyses (

            filename,
            sha256,
            file_size,
            analysis_date,
            risk_score,
            risk_level,
            yara_matches,
            report_path

        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,

        (
            filename,
            sha256,
            file_size,
            analysis_date,
            risk_score,
            risk_level,
            yara_matches,
            report_path
        )
    )

    connection.commit()

    connection.close()


# ==========================
# GET ANALYSIS HISTORY
# ==========================

def get_analysis_history():

    initialize_database()

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            filename,
            sha256,
            file_size,
            analysis_date,
            risk_score,
            risk_level,
            yara_matches,
            report_path

        FROM analyses

        ORDER BY id DESC
        """
    )

    results = cursor.fetchall()

    connection.close()

    return results


# ==========================
# FIND EXISTING SAMPLE
# ==========================

def find_by_sha256(sha256):

    initialize_database()

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            filename,
            sha256,
            file_size,
            analysis_date,
            risk_score,
            risk_level,
            yara_matches,
            report_path

        FROM analyses

        WHERE sha256 = ?

        ORDER BY id DESC

        LIMIT 1
        """,

        (sha256,)
    )

    result = cursor.fetchone()

    connection.close()

    return result
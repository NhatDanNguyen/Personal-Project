import os

from modules.file_analyzer import (
    get_file_information,
    calculate_hashes,
    analyze_pe,
    analyze_imports,
    detect_suspicious_apis,
    extract_strings,
    extract_iocs,
    analyze_entropy,
    calculate_risk_score
)

from modules.yara_scanner import scan_file


# ============================================================
# SAMPLE VALIDATION
# ============================================================

def validate_sample(file_path):
    """
    Validate the submitted sample before analysis.
    """

    if not file_path:
        raise ValueError(
            "No sample file was provided."
        )

    if not os.path.exists(file_path):
        raise FileNotFoundError(
            "Sample file does not exist."
        )

    if not os.path.isfile(file_path):
        raise ValueError(
            "The selected path is not a file."
        )

    if not os.access(file_path, os.R_OK):
        raise PermissionError(
            "The sample cannot be read. Check file permissions."
        )

    file_size = os.path.getsize(file_path)

    if file_size == 0:
        raise ValueError(
            "The sample file is empty."
        )

    return True


# ============================================================
# MAIN ANALYSIS PIPELINE
# ============================================================

def analyze_file(file_path):

    # ========================================================
    # STEP 0: VALIDATE SAMPLE
    # ========================================================

    validate_sample(file_path)


    # ========================================================
    # STEP 1: FILE INFORMATION
    # ========================================================

    file_info = get_file_information(
        file_path
    )


    # ========================================================
    # STEP 2: HASHES
    # ========================================================

    hashes = calculate_hashes(
        file_path
    )


    # ========================================================
    # STEP 3: PE ANALYSIS
    # ========================================================

    pe_info = analyze_pe(
        file_path
    )


    # ========================================================
    # STEP 4: IMPORT ANALYSIS
    # ========================================================

    import_info = analyze_imports(
        file_path
    )


    # ========================================================
    # STEP 5: SUSPICIOUS API ANALYSIS
    # ========================================================

    api_findings = detect_suspicious_apis(
        import_info
    )


    # ========================================================
    # STEP 6: STRING ANALYSIS
    # ========================================================

    strings = extract_strings(
        file_path
    )


    # ========================================================
    # STEP 7: IOC ANALYSIS
    # ========================================================

    iocs = extract_iocs(
        strings
    )


    # ========================================================
    # STEP 8: ENTROPY ANALYSIS
    # ========================================================

    entropy_findings = analyze_entropy(
        pe_info
    )


    # ========================================================
    # STEP 9: YARA ANALYSIS
    # ========================================================

    yara_findings = scan_file(
        file_path
    )


    # ========================================================
    # STEP 10: RISK ASSESSMENT
    # ========================================================

    risk = calculate_risk_score(
        api_findings,
        entropy_findings,
        iocs,
        yara_findings
    )


    # ========================================================
    # FINAL RESULT
    # ========================================================

    return {

        "file_path": file_path,

        "file_info": file_info,

        "hashes": hashes,

        "pe_info": pe_info,

        "import_info": import_info,

        "api_findings": api_findings,

        "strings": strings,

        "iocs": iocs,

        "entropy_findings": entropy_findings,

        "yara_findings": yara_findings,

        "risk": risk

    }
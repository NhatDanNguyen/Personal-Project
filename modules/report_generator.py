import os
import time


def generate_report(
    file_path,
    file_info,
    hashes,
    pe_info,
    import_info,
    api_findings,
    iocs,
    entropy_findings,
    yara_findings,
    risk
):

    os.makedirs(
        "reports",
        exist_ok=True
    )

    filename = os.path.basename(
        file_path
    )

    report_path = os.path.join(
        "reports",
        "analysis_report.txt"
    )

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as report:

        # ==========================
        # HEADER
        # ==========================

        report.write(
            "=" * 80 + "\n"
        )

        report.write(
            "MALWARE ANALYSIS REPORT\n"
        )

        report.write(
            "=" * 80 + "\n\n"
        )

        report.write(
            f"Generated : {time.ctime()}\n"
        )

        report.write(
            f"File      : {filename}\n"
        )

        report.write(
            f"Path      : {os.path.abspath(file_path)}\n\n"
        )


        # ==========================
        # FILE INFORMATION
        # ==========================

        report.write(
            "=" * 80 + "\n"
        )

        report.write(
            "FILE INFORMATION\n"
        )

        report.write(
            "=" * 80 + "\n\n"
        )

        for key, value in file_info.items():

            report.write(
                f"{key:<20}: {value}\n"
            )

        report.write("\n")


        # ==========================
        # HASHES
        # ==========================

        report.write(
            "=" * 80 + "\n"
        )

        report.write(
            "FILE HASHES\n"
        )

        report.write(
            "=" * 80 + "\n\n"
        )

        for algorithm, value in hashes.items():

            report.write(
                f"{algorithm.upper():<20}: "
                f"{value}\n"
            )

        report.write("\n")


        # ==========================
        # PE ANALYSIS
        # ==========================

        report.write(
            "=" * 80 + "\n"
        )

        report.write(
            "PE ANALYSIS\n"
        )

        report.write(
            "=" * 80 + "\n\n"
        )

        if not pe_info.get("is_pe"):

            report.write(
                "Not a valid PE file.\n"
            )

        else:

            report.write(
                f"Architecture     : "
                f"{pe_info['architecture']}\n"
            )

            report.write(
                f"Entry Point      : "
                f"{pe_info['entry_point']}\n"
            )

            report.write(
                f"Image Base       : "
                f"{pe_info['image_base']}\n"
            )

            report.write(
                f"Compile Timestamp: "
                f"{pe_info['compile_timestamp']}\n\n"
            )


            report.write(
                "SECTIONS\n"
            )

            report.write(
                "-" * 80 + "\n"
            )

            for section in pe_info["sections"]:

                report.write(
                    f"{section['name']:<12}"
                    f"Entropy: "
                    f"{section['entropy']:<6}"
                    f"Raw Size: "
                    f"{section['raw_size']}\n"
                )

        report.write("\n")


        # ==========================
        # IMPORTS
        # ==========================

        report.write(
            "=" * 80 + "\n"
        )

        report.write(
            "IMPORTED DLLs AND APIs\n"
        )

        report.write(
            "=" * 80 + "\n\n"
        )

        if import_info["imports"]:

            for dll in import_info["imports"]:

                report.write(
                    f"[{dll['dll']}]\n"
                )

                for function in dll["functions"]:

                    report.write(
                        f"    {function}\n"
                    )

                report.write("\n")

        else:

            report.write(
                "No imports found.\n\n"
            )


        # ==========================
        # SUSPICIOUS APIs
        # ==========================

        report.write(
            "=" * 80 + "\n"
        )

        report.write(
            "SUSPICIOUS API FINDINGS\n"
        )

        report.write(
            "=" * 80 + "\n\n"
        )

        if not api_findings:

            report.write(
                "No suspicious APIs detected.\n\n"
            )

        else:

            for finding in api_findings:

                report.write(
                    f"[{finding['category']}]\n"
                )

                for api in finding["apis"]:

                    report.write(
                        f"    {api}\n"
                    )

                report.write("\n")


        # ==========================
        # IOCs
        # ==========================

        report.write(
            "=" * 80 + "\n"
        )

        report.write(
            "INDICATORS OF COMPROMISE\n"
        )

        report.write(
            "=" * 80 + "\n\n"
        )

        for category, values in iocs.items():

            report.write(
                f"{category.upper()}\n"
            )

            report.write(
                "-" * 40 + "\n"
            )

            if values:

                for value in values:

                    report.write(
                        f"    {value}\n"
                    )

            else:

                report.write(
                    "    None detected\n"
                )

            report.write("\n")


        # ==========================
        # ENTROPY
        # ==========================

        report.write(
            "=" * 80 + "\n"
        )

        report.write(
            "ENTROPY FINDINGS\n"
        )

        report.write(
            "=" * 80 + "\n\n"
        )

        if not entropy_findings:

            report.write(
                "No unusually high entropy "
                "sections detected.\n\n"
            )

        else:

            for finding in entropy_findings:

                report.write(
                    f"[{finding['severity']}] "
                    f"{finding['section']}\n"
                )

                report.write(
                    f"Entropy : "
                    f"{finding['entropy']}\n"
                )

                report.write(
                    f"Finding : "
                    f"{finding['message']}\n\n"
                )
        # ==========================
        # YARA ANALYSIS
        # ==========================

        report.write(
            "=" * 80 + "\n"
        )

        report.write(
            "YARA ANALYSIS\n"
        )

        report.write(
            "=" * 80 + "\n\n"
        )

        if not yara_findings:

            report.write(
                "No YARA rules matched.\n\n"
            )

        else:

            for finding in yara_findings:

                report.write(
                    f"Rule        : "
                    f"{finding['rule']}\n"
                )

                report.write(
                    f"Severity    : "
                    f"{finding['severity']}\n"
                )

                report.write(
                    f"Description : "
                    f"{finding['description']}\n"
                )

                report.write(
                    "Matches:\n"
                )

                for match in finding["matches"]:

                    report.write(
                        f"    {match['identifier']} "
                        f"-> {match['value']}\n"
                    )

                report.write(
                    "\n"
                )

        # ==========================
        # RISK ASSESSMENT
        # ==========================

        report.write(
            "=" * 80 + "\n"
        )

        report.write(
            "RISK ASSESSMENT\n"
        )

        report.write(
            "=" * 80 + "\n\n"
        )

        report.write(
            f"Risk Score : "
            f"{risk['score']} / 100\n"
        )

        report.write(
            f"Risk Level : "
            f"{risk['level']}\n\n"
        )


        report.write(
            "INDICATORS CONTRIBUTING TO SCORE\n"
        )

        report.write(
            "-" * 80 + "\n"
        )

        if risk["indicators"]:

            for indicator in risk["indicators"]:

                report.write(
                    f"[{indicator['severity']}] "
                    f"+{indicator['points']} "
                    f"{indicator['message']}\n"
                )

        else:

            report.write(
                "No suspicious indicators detected.\n"
            )


        report.write("\n")

        report.write(
            "=" * 80 + "\n"
        )

        report.write(
            "END OF REPORT\n"
        )

        report.write(
            "=" * 80 + "\n"
        )


    return report_path
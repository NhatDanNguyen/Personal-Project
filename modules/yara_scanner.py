import yara
import os


# ==========================
# YARA RULE PATH
# ==========================

RULE_PATH = os.path.join(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    ),
    "rules",
    "basic_rules.yar"
)


# ==========================
# LOAD YARA RULES
# ==========================

def load_rules():

    return yara.compile(
        filepath=RULE_PATH
    )


# ==========================
# SCAN FILE
# ==========================

def scan_file(file_path):

    rules = load_rules()

    matches = rules.match(
        file_path
    )

    findings = []


    # ==========================
    # PROCESS MATCHES
    # ==========================

    for match in matches:

        severity = match.meta.get(
            "severity",
            "medium"
        ).upper()

        description = match.meta.get(
            "description",
            "No description available"
        )


        matched_strings = []


        # ==========================
        # EXTRACT MATCHED STRINGS
        # ==========================

        for string in match.strings:

            try:

                identifier = string.identifier


                for instance in string.instances:

                    matched_data = (
                        instance.matched_data
                    )


                    value = matched_data.decode(
                        "utf-8",
                        errors="ignore"
                    )


                    matched_strings.append({

                        "identifier":
                            identifier,

                        "value":
                            value

                    })


            except AttributeError:

                # Compatibility fallback
                # for different YARA versions

                matched_strings.append({

                    "identifier":
                        str(string),

                    "value":
                        str(string)

                })


        # ==========================
        # STORE FINDING
        # ==========================

        findings.append({

            "rule":
                match.rule,

            "severity":
                severity,

            "description":
                description,

            "matches":
                matched_strings

        })


    return findings
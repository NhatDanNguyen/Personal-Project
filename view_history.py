from modules.database import get_analysis_history


history = get_analysis_history()


print("=" * 80)
print("MALWARE ANALYSIS HISTORY")
print("=" * 80)


if not history:

    print("No analyses found.")

else:

    for item in history:

        print()
        print(f"ID          : {item[0]}")
        print(f"Filename    : {item[1]}")
        print(f"SHA256      : {item[2]}")
        print(f"File Size   : {item[3]}")
        print(f"Date        : {item[4]}")
        print(f"Risk Score  : {item[5]}")
        print(f"Risk Level  : {item[6]}")
        print(f"YARA Matches: {item[7]}")
        print(f"Report      : {item[8]}")
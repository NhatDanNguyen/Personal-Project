import tkinter as tk
from tkinter import filedialog, messagebox
import os
import threading

from modules.analyzer import analyze_file
from modules.report_generator import generate_report
from modules.database import (
    save_analysis,
    find_by_sha256
)
from modules.file_analyzer import calculate_hashes


# ============================================================
# MAIN WINDOW
# ============================================================

window = tk.Tk()

window.title(
    "Malware Analysis Sandbox"
)

window.geometry(
    "900x650"
)

window.minsize(
    800,
    550
)

window.configure(
    bg="#f3f4f6"
)


# ============================================================
# TITLE
# ============================================================

title_label = tk.Label(
    window,
    text="Malware Analysis Sandbox",
    font=("Arial", 24, "bold"),
    bg="#f3f4f6",
    fg="#111827"
)

title_label.pack(
    pady=(30, 5)
)


subtitle_label = tk.Label(
    window,
    text="Static Malware Analysis Environment",
    font=("Arial", 11),
    bg="#f3f4f6",
    fg="#6b7280"
)

subtitle_label.pack(
    pady=(0, 25)
)


# ============================================================
# FILE SELECTION
# ============================================================

file_frame = tk.Frame(
    window,
    bg="white",
    bd=1,
    relief="solid"
)

file_frame.pack(
    padx=50,
    pady=10,
    fill="x"
)


file_title = tk.Label(
    file_frame,
    text="Select Sample",
    font=("Arial", 14, "bold"),
    bg="white",
    fg="#111827"
)

file_title.pack(
    anchor="w",
    padx=20,
    pady=(18, 10)
)


selected_file = tk.StringVar()

selected_file.set(
    "No file selected"
)


file_entry = tk.Entry(
    file_frame,
    textvariable=selected_file,
    font=("Arial", 10),
    state="readonly",
    readonlybackground="white"
)

file_entry.pack(
    side="left",
    padx=(20, 10),
    pady=(0, 20),
    fill="x",
    expand=True
)


# ============================================================
# STATUS
# ============================================================

status_frame = tk.Frame(
    window,
    bg="white",
    bd=1,
    relief="solid"
)

status_frame.pack(
    padx=50,
    pady=15,
    fill="x"
)


status_title = tk.Label(
    status_frame,
    text="Status",
    font=("Arial", 13, "bold"),
    bg="white",
    fg="#111827"
)

status_title.pack(
    anchor="w",
    padx=20,
    pady=(15, 5)
)


status_label = tk.Label(
    status_frame,
    text="Ready",
    font=("Arial", 11),
    bg="white",
    fg="#6b7280"
)

status_label.pack(
    anchor="w",
    padx=20,
    pady=(0, 15)
)


# ============================================================
# RESULTS
# ============================================================

results_frame = tk.Frame(
    window,
    bg="white",
    bd=1,
    relief="solid"
)

results_frame.pack(
    padx=50,
    pady=10,
    fill="both",
    expand=True
)


results_title = tk.Label(
    results_frame,
    text="Analysis Results",
    font=("Arial", 14, "bold"),
    bg="white",
    fg="#111827"
)

results_title.pack(
    pady=(15, 10)
)


result_label = tk.Label(
    results_frame,
    text="No analysis performed.",
    font=("Arial", 11),
    bg="white",
    fg="#6b7280",
    justify="left",
    anchor="nw"
)

result_label.pack(
    padx=30,
    pady=10,
    fill="both",
    expand=True
)


# ============================================================
# BUTTON FRAME
# ============================================================

button_frame = tk.Frame(
    window,
    bg="#f3f4f6"
)

button_frame.pack(
    pady=15
)


# ============================================================
# BROWSE
# ============================================================

def browse_file():

    file_path = filedialog.askopenfilename(

        title="Select Malware Sample",

        filetypes=[
            (
                "Executable Files",
                "*.exe"
            ),
            (
                "All Files",
                "*.*"
            )
        ]
    )

    if file_path:

        selected_file.set(
            file_path
        )

        status_label.config(
            text="Sample selected.",
            fg="#2563eb"
        )

        result_label.config(
            text="No analysis performed.",
            fg="#6b7280"
        )


browse_button = tk.Button(
    file_frame,
    text="Browse",
    width=12,
    height=2,
    command=browse_file
)

browse_button.pack(
    side="right",
    padx=(0, 20),
    pady=(0, 20)
)


# ============================================================
# UI HELPER FUNCTIONS
# ============================================================

def update_status(
    text,
    color
):

    status_label.config(
        text=text,
        fg=color
    )


def show_error(
    message
):

    update_status(
        "Analysis failed.",
        "#dc2626"
    )

    result_label.config(
        text=message,
        fg="#dc2626"
    )

    analyze_button.config(
        state="normal"
    )

    messagebox.showerror(
        "Analysis Error",
        message
    )


# ============================================================
# DUPLICATE RESULT
# ============================================================

def show_duplicate(
    existing_analysis
):

    result_text = (

        "SAMPLE ALREADY ANALYZED\n\n"

        f"Filename     : "
        f"{existing_analysis[1]}\n"

        f"SHA256       : "
        f"{existing_analysis[2]}\n"

        f"File Size    : "
        f"{existing_analysis[3]}\n"

        f"Analysis Date: "
        f"{existing_analysis[4]}\n"

        f"Risk Score   : "
        f"{existing_analysis[5]} / 100\n"

        f"Risk Level   : "
        f"{existing_analysis[6]}\n"

        f"YARA Matches : "
        f"{existing_analysis[7]}\n\n"

        f"Report       : "
        f"{existing_analysis[8]}"
    )

    result_label.config(
        text=result_text,
        fg="#d97706"
    )

    update_status(
        "Sample already analyzed.",
        "#d97706"
    )

    analyze_button.config(
        state="normal"
    )


# ============================================================
# ANALYSIS WORKER
# ============================================================

def analysis_worker(
    file_path
):

    try:

        # ----------------------------------------------------
        # STEP 1: Calculate SHA256
        # ----------------------------------------------------

        window.after(
            0,
            update_status,
            "Calculating file hash...",
            "#2563eb"
        )

        hashes = calculate_hashes(
            file_path
        )

        sha256 = hashes["sha256"]


        # ----------------------------------------------------
        # STEP 2: Check database
        # ----------------------------------------------------

        window.after(
            0,
            update_status,
            "Checking analysis history...",
            "#2563eb"
        )

        existing_analysis = find_by_sha256(
            sha256
        )


        if existing_analysis:

            window.after(
                0,
                show_duplicate,
                existing_analysis
            )

            return


        # ----------------------------------------------------
        # STEP 3: Full analysis
        # ----------------------------------------------------

        window.after(
            0,
            update_status,
            "Running static analysis...",
            "#d97706"
        )

        result = analyze_file(
            file_path
        )


        # ----------------------------------------------------
        # STEP 4: Generate report
        # ----------------------------------------------------

        window.after(
            0,
            update_status,
            "Generating analysis report...",
            "#d97706"
        )

        report_path = generate_report(

            file_path,

            result["file_info"],

            result["hashes"],

            result["pe_info"],

            result["import_info"],

            result["api_findings"],

            result["iocs"],

            result["entropy_findings"],

            result["yara_findings"],

            result["risk"]

        )


        # ----------------------------------------------------
        # STEP 5: Save database
        # ----------------------------------------------------

        window.after(
            0,
            update_status,
            "Saving analysis to database...",
            "#d97706"
        )

        save_analysis(

            filename=result["file_info"]["filename"],

            sha256=result["hashes"]["sha256"],

            file_size=result["file_info"]["size"],

            risk_score=result["risk"]["score"],

            risk_level=result["risk"]["level"],

            yara_matches=len(
                result["yara_findings"]
            ),

            report_path=report_path

        )


        # ----------------------------------------------------
        # STEP 6: Display results
        # ----------------------------------------------------

        window.after(
            0,
            show_analysis_result,
            result,
            report_path
        )


    except Exception as error:

        window.after(
            0,
            show_error,
            str(error)
        )


# ============================================================
# DISPLAY ANALYSIS RESULT
# ============================================================

def show_analysis_result(
    result,
    report_path
):

    score = result["risk"]["score"]

    level = result["risk"]["level"]

    yara_count = len(
        result["yara_findings"]
    )

    file_info = result["file_info"]

    hashes = result["hashes"]

    iocs = result["iocs"]


    result_text = (

        "ANALYSIS COMPLETE\n\n"

        f"Filename     : "
        f"{file_info['filename']}\n"

        f"File Size    : "
        f"{file_info['size']} bytes\n\n"

        f"SHA256       : "
        f"{hashes['sha256']}\n\n"

        f"Risk Score   : "
        f"{score} / 100\n"

        f"Risk Level   : "
        f"{level}\n\n"

        f"YARA Matches : "
        f"{yara_count}\n\n"

        f"URLs         : "
        f"{len(iocs.get('urls', []))}\n"

        f"IP Addresses : "
        f"{len(iocs.get('ip_addresses', []))}\n"

        f"File Paths   : "
        f"{len(iocs.get('file_paths', []))}\n\n"

        f"Report       : "
        f"{report_path}"
    )


    # --------------------------------------------------------
    # Risk color
    # --------------------------------------------------------

    if level == "HIGH":

        result_color = "#dc2626"

    elif level == "MEDIUM":

        result_color = "#d97706"

    else:

        result_color = "#16a34a"


    result_label.config(
        text=result_text,
        fg=result_color
    )


    update_status(
        "Analysis completed successfully.",
        "#16a34a"
    )


    analyze_button.config(
        state="normal"
    )


# ============================================================
# ANALYZE BUTTON
# ============================================================

def analyze_sample():

    file_path = selected_file.get()


    # --------------------------------------------------------
    # Validate selection
    # --------------------------------------------------------

    if file_path == "No file selected":

        messagebox.showwarning(
            "No Sample Selected",
            "Please select an executable file first."
        )

        return


    # --------------------------------------------------------
    # Validate file
    # --------------------------------------------------------

    if not os.path.exists(file_path):

        messagebox.showerror(
            "File Error",
            "The selected file no longer exists."
        )

        return


    # --------------------------------------------------------
    # Disable button
    # --------------------------------------------------------

    analyze_button.config(
        state="disabled"
    )


    status_label.config(
        text="Starting analysis...",
        fg="#2563eb"
    )


    result_label.config(
        text="Analysis in progress...",
        fg="#2563eb"
    )


    # --------------------------------------------------------
    # Start background thread
    # --------------------------------------------------------

    thread = threading.Thread(

        target=analysis_worker,

        args=(file_path,),

        daemon=True

    )

    thread.start()


analyze_button = tk.Button(
    button_frame,
    text="ANALYZE SAMPLE",
    font=("Arial", 12, "bold"),
    width=25,
    height=2,
    command=analyze_sample
)

analyze_button.pack()


# ============================================================
# FOOTER
# ============================================================

footer = tk.Label(
    window,
    text="Static analysis only • Samples are never executed",
    font=("Arial", 9),
    bg="#f3f4f6",
    fg="#6b7280"
)

footer.pack(
    pady=(0, 15)
)


# ============================================================
# START APPLICATION
# ============================================================

window.mainloop()
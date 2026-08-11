# Malware Analysis Sandbox

A Python-based **static malware analysis sandbox** designed to inspect Windows PE/EXE samples without executing them.

The project combines file metadata analysis, cryptographic hashing, PE analysis, import/API inspection, string and IOC extraction, entropy analysis, YARA scanning, risk scoring, reporting, and analysis history into a single analysis pipeline.

> ⚠️ **Safety Notice:** This project performs static analysis only. Submitted samples are not executed by the sandbox.

---

## Features

### 🔍 Static File Analysis

The sandbox extracts basic information about a submitted sample:

- Filename
- File size
- File path
- MD5
- SHA1
- SHA256

### 🧬 PE Analysis

Windows Portable Executable files are inspected for:

- Architecture
- Entry point
- Image base
- Compile timestamp
- PE sections
- Section entropy
- Raw section sizes

### 📦 Import Analysis

The sandbox analyzes imported DLLs and functions to identify potentially suspicious capabilities.

Examples include:

- Process manipulation
- File operations
- Command execution
- Network-related functionality
- Persistence-related APIs

### 🔎 String & IOC Extraction

Extracted strings are analyzed for indicators such as:

- URLs
- IP addresses
- Email addresses
- File paths
- Registry paths
- PowerShell references
- Command references

### 📊 Entropy Analysis

PE sections are analyzed using Shannon entropy.

High-entropy sections can indicate:

- Compression
- Encryption
- Packed content

Entropy is treated as an indicator rather than definitive proof of malicious behavior.

### 🧪 YARA Scanning

The sandbox supports custom YARA rules for detecting suspicious patterns.

Each YARA finding can contain:

- Rule name
- Severity
- Description
- Matched strings

Rules are stored in:

```text
rules/
└── basic_rules.yar

⚠️ Risk Assessment

The risk engine combines multiple static indicators into a score from:

0 - 100

Risk levels are classified as:

Score	Risk Level
0–39	LOW
40–69	MEDIUM
70–100	HIGH

The risk engine considers indicators such as:

Suspicious APIs
Process manipulation
Command execution
File operations
High entropy
URLs
IP addresses
PowerShell references
Suspicious commands
YARA matches

The final score is capped at 100.

🗄️ Analysis History

Analysis results can be stored locally using SQLite.

The database stores information including:

Filename
SHA256
File size
Analysis date
Risk score
Risk level
YARA match count
Report path

SHA256-based duplicate detection is also supported.

📄 Report Generation

Each completed analysis can generate a text-based report containing the major findings and risk assessment.

Analysis Pipeline
                         SAMPLE
                            │
                            ▼
                  ┌───────────────────┐
                  │ Sample Validation │
                  └─────────┬─────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │ File Information  │
                  └─────────┬─────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │     Hashing       │
                  │ MD5/SHA1/SHA256   │
                  └─────────┬─────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │    PE Analysis    │
                  └─────────┬─────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │ Import Analysis   │
                  └─────────┬─────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │ Suspicious API    │
                  │     Detection     │
                  └─────────┬─────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │ String Analysis   │
                  └─────────┬─────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │    IOC Scan       │
                  └─────────┬─────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │ Entropy Analysis  │
                  └─────────┬─────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │    YARA Scan      │
                  └─────────┬─────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │    Risk Engine    │
                  └─────────┬─────────┘
                            │
                  ┌─────────┴─────────┐
                  ▼                   ▼
          ┌──────────────┐     ┌──────────────┐
          │    Report    │     │   Database   │
          └──────────────┘     └──────────────┘
Project Structure
Malware_Analysis_Sandbox/
│
├── app.py
│
├── modules/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── database.py
│   ├── file_analyzer.py
│   ├── report_generator.py
│   └── yara_scanner.py
│
├── rules/
│   └── basic_rules.yar
│
├── samples/
│   └── test_sample.py
│
├── tests/
│   ├── __init__.py
│   ├── test_analyzer.py
│   ├── test_analyzer_validation.py
│   ├── test_database.py
│   ├── test_file_analyzer.py
│   ├── test_pe_analysis.py
│   ├── test_risk.py
│   └── test_yara.py
│
├── ui/
│   └── sandbox_page.py
│
├── test_sample.spec
├── view_history.py
├── pytest.ini
├── requirements.txt
├── requirements-dev.txt
├── .gitignore
└── README.md
Technology Stack
Python 3.12+
Tkinter for the current desktop interface
pefile for Windows PE analysis
yara-python for YARA scanning
SQLite for analysis history
pytest for automated testing
PyInstaller for optional executable packaging
Installation
1. Clone the Repository
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd Malware_Analysis_Sandbox
2. Create a Virtual Environment

On Windows:

python -m venv .venv

Activate the environment:

.venv\Scripts\activate
3. Install Dependencies

Install the main project dependencies:

python -m pip install -r requirements.txt

For development and testing dependencies:

python -m pip install -r requirements-dev.txt
Running the Sandbox

Start the application using:

python app.py

The current application provides a desktop interface for:

Selecting a sample
Starting static analysis
Displaying analysis status
Displaying analysis results
Detecting previously analyzed samples
Running the Analysis Pipeline

The analysis pipeline can also be tested directly.

The pipeline performs:

File information extraction
Hash calculation
PE analysis
Import analysis
Suspicious API detection
String extraction
IOC extraction
Entropy analysis
YARA scanning
Risk assessment
Report generation
Database storage
YARA Rules

YARA rules are stored inside:

rules/

The current rule set contains rules for detecting suspicious static indicators.

Example:

Suspicious_Network_Activity

YARA findings are incorporated into the overall risk assessment.

Risk Scoring

The risk engine assigns points based on detected indicators.

Examples include:

Indicator	Example Weight
Process Injection	+30
Persistence	+20
Command Execution	+20
Network Communication	+15
Process Manipulation	+15
File Operations	+5
High Entropy	+20
Medium Entropy	+10
URL	+5 each, capped
IP Address	+5 each, capped
PowerShell	+15
Suspicious Command	+10
High Severity YARA	+20
Medium Severity YARA	+10
Low Severity YARA	+5

The score is capped at:

100

Risk classification:

0 - 39    LOW
40 - 69   MEDIUM
70 - 100  HIGH

The risk engine also records the indicators contributing to the final score.

Database

The project uses SQLite to maintain local analysis history.

Database location:

database/sandbox.db

The database stores:

ID
Filename
SHA256
File Size
Analysis Date
Risk Score
Risk Level
YARA Matches
Report Path
Duplicate Detection

Before performing unnecessary repeated analysis, the project can use the SHA256 hash of a sample to determine whether the same sample has already been analyzed.

This prevents identical files from being treated as completely new samples.

Reports

Analysis reports are generated automatically after analysis.

Reports contain information such as:

File Information
Hashes
PE Information
PE Sections
Imported DLLs
Suspicious APIs
URLs
IP Addresses
File Paths
Registry Paths
PowerShell Indicators
Command Indicators
Entropy Findings
YARA Findings
Risk Score
Risk Level
Risk Indicators
Testing

The project includes an automated testing suite using pytest.

Tests currently cover:

File information
MD5 hashing
SHA1 hashing
SHA256 hashing
PE analysis
PE architecture detection
PE entry point detection
YARA scanning
YARA finding structure
Risk scoring
Risk level classification
Risk score limits
URL indicators
IP address indicators
PowerShell indicators
Command execution indicators
Multiple risk indicators
Database operations
Analysis history
SHA256 duplicate detection
Analyzer validation
Complete analysis pipeline

Run the complete test suite with:

python -m pytest -v

Current test status:

41 passed
Example Output

A completed static analysis can produce output similar to:

======================================================================
MALWARE ANALYSIS PIPELINE
======================================================================

FILE
------------------------------
Filename: test_sample.exe
Size: 8894713

HASHES
------------------------------
MD5: 47b8a1d09f374aeb786fd7fba0317410
SHA1: 774408f5351cfbbe6308c82fae18a9b4dc175fc9
SHA256: e7d0e1d774d4e92ea1fc3d2c04f4413ae8c9ef70d934cbc939a454711b5194ce

PE ANALYSIS
------------------------------
Architecture: x64 (64-bit)
Entry Point: 0xd6c0

SUSPICIOUS APIs
------------------------------
Process Manipulation: CreateProcessW, TerminateProcess
File Operations: CreateFileW, WriteFile, DeleteFileW
Command Execution: CreateProcessW

YARA ANALYSIS
------------------------------
Suspicious_Network_Activity

RISK ASSESSMENT
------------------------------
Score: 75 / 100
Level: HIGH

REPORT
------------------------------
Report generated: reports/analysis_report.txt
Current Limitations

Version 1 currently focuses on static analysis.

The project does not currently provide:

Dynamic malware execution
Process behavior monitoring
Network traffic capture
Registry behavior monitoring
API hooking
Memory analysis
Automated virtual machine execution
Cloud malware reputation lookup
Full behavioral sandboxing

These features may be considered for future versions.

Security Considerations

This project is intended for educational, research, and defensive cybersecurity purposes.

The current sandbox performs static analysis and does not execute submitted samples.

However, malware samples should still be handled carefully.

Recommended practices include:

Use an isolated environment for malware research.
Never execute unknown samples on your primary machine.
Keep analysis environments separated from personal systems.
Do not open malicious samples outside the intended analysis environment.
Treat extracted URLs, commands, and file paths as potentially untrusted data.

The project should not currently be considered a production-grade malware detonation platform.

Roadmap
Version 1.0
 Project structure
 File metadata analysis
 MD5/SHA1/SHA256 hashing
 PE analysis
 Import analysis
 Suspicious API detection
 String extraction
 IOC extraction
 Entropy analysis
 YARA scanning
 Risk scoring
 Risk indicator generation
 Report generation
 SQLite analysis history
 SHA256 duplicate detection
 Sample validation
 Desktop UI
 Automated testing
 Git-ready project structure
Future Versions
Version 1.1
 Improved report formatting
 More YARA rules
 Better IOC classification
 Improved UI
 Searchable analysis history
 Exportable analysis results
Version 2.0
 React-based frontend
 REST API
 Interactive analysis dashboard
 MITRE ATT&CK mapping
 Threat intelligence integration
 Advanced YARA management
Future Research
 Dynamic analysis
 Process monitoring
 Network behavior monitoring
 Registry monitoring
 Memory analysis
 VM-based malware isolation
 Automated behavioral analysis
Project Goals

The main goal of this project is to build a practical malware-analysis environment that demonstrates how multiple static-analysis techniques can be combined into a single workflow.

The project focuses on:

Sample
   ↓
Evidence Collection
   ↓
Static Analysis
   ↓
Indicator Detection
   ↓
Risk Assessment
   ↓
Report
   ↓
Analysis History

Rather than relying on a single detection mechanism, the sandbox combines multiple independent indicators to produce a more informative analysis result.

Disclaimer

This project is intended for educational, research, and defensive cybersecurity purposes.

It is not intended to replace professional malware-analysis platforms or enterprise security products.

The author is not responsible for damage, data loss, system compromise, or other consequences resulting from improper handling of malicious files.

Always use appropriate isolation and security controls when working with potentially malicious samples.

License

This project is intended to be released under the MIT License.

See the LICENSE file for details.
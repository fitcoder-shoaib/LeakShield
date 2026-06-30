LeakShield – AI Data Risk & Compliance Assistant

LeakShield is a privacy-first web application that scans documents for sensitive information such as personally identifiable information (PII), financial data, and credentials. It assigns a risk score, explains why the file is risky, provides security recommendations, and generates redacted copies to prevent accidental data leaks.

The application is designed to be simple, explainable, and suitable for compliance-heavy industries such as healthcare, finance, and education.

⸻

FEATURES

• Multi-file upload support
• Scans text, logs, JSON, CSV, PDF, Word, Excel, PowerPoint, email, and image files
• Detection of PII, identity documents, financial data, credentials, health data, and location data
• Context-aware risk scoring (Low / Medium / High)
• Explainable “why is this risky?” output
• Automated redacted file generation
• Temporary scan history with auto-delete
• Manual history clear option
• Privacy-first design (no permanent data storage)

LeakShield detects common forms of sensitive data including passwords, password hashes, PINs, OTPs, SSNs, national IDs, Aadhaar numbers, passport numbers, driver license numbers, bank account numbers, credit card numbers, CVVs, emails, phone numbers, addresses, dates of birth, medical records, salary values, tax IDs, API keys, private keys, access tokens, refresh tokens, GPS locations, and biometric indicators.

⸻

SUPPORTED FILE TYPES

LeakShield can scan:

• Text and structured text: .txt, .log, .json, .csv
• Documents: .pdf, .doc, .docx
• Spreadsheets: .xlsx
• Presentations: .pptx
• Email files: .eml, .msg
• Images and screenshots: .png, .jpg, .jpeg, .webp, .tif, .tiff, .bmp

Notes:

• Image scanning uses OCR and requires the Tesseract system binary.
• Legacy .doc scanning requires antiword on Linux, or textutil on macOS.
• Modern Office files use Python libraries: python-docx, openpyxl, and python-pptx.

⸻

TECH STACK

• Python
• Streamlit – web UI and application server
• Pandas – structured data handling and reporting
• pdfplumber – PDF text extraction
• python-docx – Word document parsing
• openpyxl – Excel spreadsheet parsing
• python-pptx – PowerPoint parsing
• extract-msg – Outlook .msg email parsing
• pytesseract + Tesseract OCR – image and screenshot text extraction
• Pillow – image and logo handling

⸻

SYSTEM REQUIREMENTS

• Linux (Ubuntu 20.04 or 22.04 recommended)
• Python 3.9 or higher
• Git

⸻

SETUP AND INSTALLATION (FRESH LINUX MACHINE)

Step 1: Update system packages

apt update && apt upgrade -y

Step 2: Install required system dependencies

apt install -y python3 python3-pip python3-venv build-essential git tesseract-ocr antiword

On macOS, install OCR and legacy Word support with:

brew install tesseract antiword

Verify installation:

python3 --version
pip3 --version
git --version
tesseract --version

Step 3: Clone the GitHub repository

git clone https://github.com/fitcoder-shoaib/LeakShield.git
cd LeakShield

Step 4: Create and activate a Python virtual environment

python3 -m venv venv
source venv/bin/activate

After activation, the terminal prompt should show (venv).

Step 5: Install Python dependencies

pip install -r requirements.txt

Step 6: Run the web application

streamlit run app.py --server.port=8501 --server.address=0.0.0.0

Step 7: Run the command line tool directly

./leakshield scan document.txt report.pdf notes.docx sheet.xlsx slides.pptx email.eml screenshot.png

Step 8: Optional: install the command line tool locally

pip install -e .

After installation, scan files from anywhere with:

leakshield scan document.txt report.pdf notes.docx sheet.xlsx slides.pptx email.eml screenshot.png

Write redacted text copies into a folder:

leakshield scan document.txt --redact-dir redacted

Print JSON output for scripts or CI:

leakshield scan document.txt --json

Fail with exit code 2 when a file reaches Medium or High risk:

leakshield scan document.txt --fail-on-risk Medium

⸻

ACCESSING THE APPLICATION

From a browser, open:

For local usage:
http://localhost:8501

For cloud usage:
http://SERVER_IP:8501

⸻

PRIVACY AND SECURITY NOTES

• Files are processed entirely in memory
• Uploaded data is not stored permanently
• Scan history automatically deletes after a short duration
• Users can manually clear scan history at any time

⸻

PROJECT PHILOSOPHY

LeakShield uses rule-based and explainable AI principles rather than black-box machine learning models. This ensures transparency, auditability, and trust, which are critical for security and compliance use cases.

The system focuses on preventing human error, which is the leading cause of data breaches.

⸻

FUTURE ENHANCEMENTS

• Industry-specific scanning modes (Healthcare, Finance, HR)
• Advanced NLP-based document classification
• Bulk folder scanning
• Integration with email and cloud storage platforms

⸻

AUTHOR

Developed as part of a hackathon project focused on data privacy, security, and compliance awareness.

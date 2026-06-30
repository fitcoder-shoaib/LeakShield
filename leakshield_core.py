import re
from pathlib import Path


PATTERNS = {
    "PII": {
        "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}",
        "Phone": r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b",
        "Aadhaar": r"\b[2-9][0-9]{11}\b",
    },
    "Financial": {
        "PAN": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
    },
    "Credentials": {
        "Password": r"(?:password|pwd|pass)\s*[\:\=\-]\s*\S+",
        "API Key": r"\b[A-Za-z0-9]{32,40}\b",
    },
}

WEIGHTS = {"PII": 2, "Financial": 4, "Credentials": 5}
SUPPORTED_EXTENSIONS = {".txt", ".log", ".json", ".pdf", ".docx"}


def analyze_document(text):
    findings, reasons = {}, []
    score = 0

    for category, items in PATTERNS.items():
        findings[category] = {}
        count = 0

        for label, pattern in items.items():
            matches = re.findall(pattern, text, flags=re.IGNORECASE)
            if matches:
                findings[category][label] = matches
                count += len(matches)

        if count:
            score += count * WEIGHTS[category]
            reasons.append(f"{count} {category} data item(s) detected")

    score = min(score, 100)
    level = "Low" if score == 0 else "Medium" if score <= 50 else "High"
    return findings, reasons, score, level


def generate_recommendations(findings):
    recs = []

    if findings["Credentials"]:
        recs.append("Rotate exposed passwords or API keys immediately.")
    if findings["Financial"]:
        recs.append("Mask or redact financial identifiers before sharing.")
    if findings["PII"]:
        recs.append("Anonymize personal data such as emails, phone numbers, and Aadhaar.")
    if not recs:
        recs.append("No sensitive data detected. Document appears safe.")

    recs.append("Encrypt sensitive files and restrict access permissions.")
    return recs


def redact_text(text):
    text = re.sub(PATTERNS["PII"]["Aadhaar"], "XXXX-XXXX-XXXX", text)
    text = re.sub(PATTERNS["PII"]["Phone"], "XXXXXXXXXX", text)
    text = re.sub(PATTERNS["Financial"]["PAN"], "XXXXX1234X", text)
    text = re.sub(PATTERNS["Financial"]["Credit Card"], "**** **** **** 5678", text)
    text = re.sub(PATTERNS["Credentials"]["Password"], "password=******", text)
    text = re.sub(PATTERNS["Credentials"]["API Key"], "API_KEY_REDACTED", text)
    text = re.sub(
        PATTERNS["PII"]["Email"],
        lambda m: m.group()[0] + "***@" + m.group().split("@")[1],
        text,
    )
    return text


def read_path(path):
    path = Path(path)
    suffix = path.suffix.lower()

    if suffix in {".txt", ".log", ".json"}:
        return path.read_text(errors="ignore")

    if suffix == ".pdf":
        import pdfplumber

        with pdfplumber.open(path) as pdf:
            return "\n".join(page.extract_text() or "" for page in pdf.pages)

    if suffix == ".docx":
        from docx import Document

        doc = Document(path)
        return "\n".join(p.text for p in doc.paragraphs)

    raise ValueError(f"Unsupported file type: {path.suffix or 'no extension'}")


def read_uploaded_file(file):
    suffix = Path(file.name).suffix.lower()

    if suffix in {".txt", ".log", ".json"}:
        return file.read().decode(errors="ignore")

    if suffix == ".pdf":
        import pdfplumber

        with pdfplumber.open(file) as pdf:
            return "\n".join(page.extract_text() or "" for page in pdf.pages)

    if suffix == ".docx":
        from docx import Document

        doc = Document(file)
        return "\n".join(p.text for p in doc.paragraphs)

    return ""


def scan_text(text):
    findings, reasons, score, level = analyze_document(text)
    return {
        "findings": findings,
        "reasons": reasons,
        "score": score,
        "risk": level,
        "recommendations": generate_recommendations(findings),
        "redacted": redact_text(text),
    }


def scan_path(path):
    path = Path(path)
    text = read_path(path)
    result = scan_text(text)
    result["file"] = str(path)
    return result

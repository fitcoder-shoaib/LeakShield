import streamlit as st
import re
import pandas as pd
import time
import pdfplumber
from docx import Document
from PIL import Image
import os

# =========================================================
# LeakShield – AI Data Risk & Compliance Assistant
# FINAL VERSION (Circular Logo + Blue Theme + Windows Safe)
# =========================================================

AUTO_DELETE_SECONDS = 15 * 60  # 15 minutes

# ---------------------- Page Setup ---------------------- #
st.set_page_config(
    page_title="LeakShield – Data Risk Detector",
    layout="centered",
    page_icon="🔒"
)

# ---------------------- Global Styling ---------------------- #
st.markdown("""
<style>
[data-testid="stAppViewContainer"] {
    background: linear-gradient(180deg, #020617 0%, #0f172a 40%, #1e3a8a 100%);
}

h1, h2, h3, h4, h5, h6, p, label, span, div {
    color: #f8fafc;
}

.stButton > button {
    background-color: #2563eb;
    color: white;
    border-radius: 8px;
}

.stButton > button:hover {
    background-color: #1d4ed8;
}

[data-testid="stFileUploader"] {
    background-color: #020617;
    padding: 12px;
    border-radius: 10px;
}

/* ---------- Circular Logo ---------- */
.logo-container {
    display: flex;
    justify-content: center;
    margin-top: 20px;
    margin-bottom: 10px;
}

.logo-container img {
    border-radius: 50%;
    width: 180px;
    height: 180px;
    object-fit: cover;
    box-shadow: 0 0 25px rgba(59,130,246,0.6);
}
</style>
""", unsafe_allow_html=True)

# ---------------------- Logo (Absolute Path) ---------------------- #
logo_path = os.path.join(os.path.dirname(__file__), "assets", "leakshield_logo.jpg")

if os.path.exists(logo_path):
    st.markdown('<div class="logo-container">', unsafe_allow_html=True)
    st.image(logo_path)
    st.markdown('</div>', unsafe_allow_html=True)
else:
    st.warning("Logo not found. Place it at assets/leakshield_logo.jpg")

st.title("LeakShield")
st.caption("AI-Powered Data Risk & Compliance Assistant")

st.write(
    "Upload one or more documents to detect sensitive data, assess risk, "
    "receive recommendations, and prevent accidental data leaks."
)

# =========================================================
# 🔍 Sensitive Data Patterns
# =========================================================

PATTERNS = {
    "PII": {
        "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}",
        "Phone": r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b",
        "Aadhaar": r"\b[2-9][0-9]{11}\b"
    },
    "Financial": {
        "PAN": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        "Credit Card": r"\b(?:\d[ -]*?){13,16}\b"
    },
    "Credentials": {
        "Password": r"(?:password|pwd|pass)\s*[\:\=\-]\s*\S+",
        "API Key": r"\b[A-Za-z0-9]{32,40}\b"
    }
}

WEIGHTS = {"PII": 2, "Financial": 4, "Credentials": 5}

# =========================================================
# 🧠 Analysis Engine
# =========================================================

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

# =========================================================
# 🛡 Recommendations
# =========================================================

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

# =========================================================
# 🛡 Redaction
# =========================================================

def redact_text(text):
    text = re.sub(PATTERNS["PII"]["Aadhaar"], "XXXX-XXXX-XXXX", text)
    text = re.sub(PATTERNS["Financial"]["PAN"], "XXXXX1234X", text)
    text = re.sub(PATTERNS["Financial"]["Credit Card"], "**** **** **** 5678", text)
    text = re.sub(PATTERNS["Credentials"]["Password"], "password=******", text)
    text = re.sub(PATTERNS["Credentials"]["API Key"], "API_KEY_REDACTED", text)
    text = re.sub(
        PATTERNS["PII"]["Email"],
        lambda m: m.group()[0] + "***@" + m.group().split("@")[1],
        text
    )
    return text

# =========================================================
# 📄 File Readers
# =========================================================

def read_file(file):
    if file.name.endswith((".txt", ".log", ".json")):
        return file.read().decode(errors="ignore")

    if file.name.endswith(".pdf"):
        with pdfplumber.open(file) as pdf:
            return "\n".join(page.extract_text() or "" for page in pdf.pages)

    if file.name.endswith(".docx"):
        doc = Document(file)
        return "\n".join(p.text for p in doc.paragraphs)

    return ""

# =========================================================
# 🕒 Scan History (Session + Auto Delete)
# =========================================================

if "history" not in st.session_state:
    st.session_state.history = []

current_time = time.time()

st.session_state.history = [
    h for h in st.session_state.history
    if current_time - h["timestamp"] < AUTO_DELETE_SECONDS
]

# =========================================================
# 📂 Multi-file Upload
# =========================================================

uploaded_files = st.file_uploader(
    "Upload files to scan",
    type=["txt", "log", "json", "pdf", "docx"],
    accept_multiple_files=True
)

if uploaded_files:
    for file in uploaded_files:
        content = read_file(file)
        findings, reasons, score, level = analyze_document(content)
        recs = generate_recommendations(findings)

        st.session_state.history.append({
            "file": file.name,
            "timestamp": current_time,
            "risk": level,
            "score": score
        })

        st.subheader(f"📄 {file.name}")
        st.write(f"**Risk Level:** {level} ({score}/100)")
        st.progress(score / 100)

        st.write("**Why is this risky?**")
        for r in reasons or ["No sensitive data detected"]:
            st.write("•", r)

        st.write("**Recommended Actions:**")
        for r in recs:
            st.write("✔", r)

        redacted = redact_text(content)
        st.download_button(
            f"⬇ Download Redacted Copy ({file.name})",
            redacted.encode(),
            file_name=f"redacted_{file.name}.txt"
        )

# =========================================================
# 📊 Scan History Dashboard + Manual Clear
# =========================================================

if st.session_state.history:
    st.subheader("📊 Scan History (Auto-clears after 15 minutes)")

    col1, col2 = st.columns([3, 1])
    with col2:
        if st.button("🧹 Clear Scan History"):
            st.session_state.history = []
            st.success("Scan history cleared.")
            st.stop()

    history_df = pd.DataFrame([
        {
            "File Name": h["file"],
            "Risk Level": h["risk"],
            "Risk Score": h["score"],
            "Scanned (mins ago)": int((current_time - h["timestamp"]) / 60)
        }
        for h in st.session_state.history
    ])

    st.dataframe(history_df, use_container_width=True)

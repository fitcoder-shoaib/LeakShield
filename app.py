import os
import time

import pandas as pd
import streamlit as st

from leakshield_core import read_uploaded_file, scan_text


AUTO_DELETE_SECONDS = 15 * 60


st.set_page_config(
    page_title="LeakShield - Data Risk Detector",
    layout="centered",
    page_icon="🔒",
)

st.markdown(
    """
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
""",
    unsafe_allow_html=True,
)

logo_path = os.path.join(os.path.dirname(__file__), "assets", "leakshield_logo.jpg")

if os.path.exists(logo_path):
    st.markdown('<div class="logo-container">', unsafe_allow_html=True)
    st.image(logo_path)
    st.markdown("</div>", unsafe_allow_html=True)
else:
    st.warning("Logo not found. Place it at assets/leakshield_logo.jpg")

st.title("LeakShield")
st.caption("AI-Powered Data Risk & Compliance Assistant")

st.write(
    "Upload one or more documents to detect sensitive data, assess risk, "
    "receive recommendations, and prevent accidental data leaks."
)

if "history" not in st.session_state:
    st.session_state.history = []

current_time = time.time()

st.session_state.history = [
    h
    for h in st.session_state.history
    if current_time - h["timestamp"] < AUTO_DELETE_SECONDS
]

uploaded_files = st.file_uploader(
    "Upload files to scan",
    type=["txt", "log", "json", "pdf", "docx"],
    accept_multiple_files=True,
)

if uploaded_files:
    for file in uploaded_files:
        content = read_uploaded_file(file)
        result = scan_text(content)

        st.session_state.history.append(
            {
                "file": file.name,
                "timestamp": current_time,
                "risk": result["risk"],
                "score": result["score"],
            }
        )

        st.subheader(f"📄 {file.name}")
        st.write(f"**Risk Level:** {result['risk']} ({result['score']}/100)")
        st.progress(result["score"] / 100)

        st.write("**Why is this risky?**")
        for reason in result["reasons"] or ["No sensitive data detected"]:
            st.write("•", reason)

        st.write("**Recommended Actions:**")
        for recommendation in result["recommendations"]:
            st.write("✔", recommendation)

        st.download_button(
            f"⬇ Download Redacted Copy ({file.name})",
            result["redacted"].encode(),
            file_name=f"redacted_{file.name}.txt",
        )

if st.session_state.history:
    st.subheader("📊 Scan History (Auto-clears after 15 minutes)")

    col1, col2 = st.columns([3, 1])
    with col2:
        if st.button("🧹 Clear Scan History"):
            st.session_state.history = []
            st.success("Scan history cleared.")
            st.stop()

    history_df = pd.DataFrame(
        [
            {
                "File Name": h["file"],
                "Risk Level": h["risk"],
                "Risk Score": h["score"],
                "Scanned (mins ago)": int((current_time - h["timestamp"]) / 60),
            }
            for h in st.session_state.history
        ]
    )

    st.dataframe(history_df, use_container_width=True)

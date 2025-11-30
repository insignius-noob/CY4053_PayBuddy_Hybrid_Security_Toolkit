import streamlit as st
import os

from core import (
    read_file_content,
    password_assessment,
    port_scan,
    enumerate_directories,
    enumerate_subdomains,
    run_stress_test,
    run_packet_capture,
    generate_report,
)

# -----------------------------
# SIMPLE CYBER THEME (dark + neon)
# -----------------------------
CYBER_STYLE = """
<style>

    /* App background */
    .stApp {
        background-color: #0b0e0f !important;
        color: #e4e4e4 !important;
    }

    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background-color: #0f1416 !important;
        border-right: 1px solid #14ffb1 !important;
    }

    /* Sidebar title + labels */
    [data-testid="stSidebar"] h1,
    [data-testid="stSidebar"] h2,
    [data-testid="stSidebar"] h3,
    [data-testid="stSidebar"] label {
        color: #14ffb1 !important;
    }

    /* Header title */
    .main-title {
        font-size: 32px;
        font-weight: 700;
        color: #14ffb1;
        margin-bottom: 6px;
    }

    .sub-title {
        font-size: 15px;
        color: #a8ffe0;
        margin-bottom: 25px;
    }

    /* Buttons */
    .stButton > button {
        background-color: #0f1416 !important;
        color: #14ffb1 !important;
        border: 1px solid #14ffb1 !important;
        border-radius: 6px;
        padding: 8px 14px;
        font-weight: 600;
    }

    .stButton > button:hover {
        background-color: #14ffb1 !important;
        color: #000 !important;
        border-color: #14ffb1 !important;
    }

    /* Terminal-style output */
    .terminal-box {
        background-color: #0f1416;
        border: 1px solid #14ffb1;
        padding: 12px;
        border-radius: 6px;
        font-family: "Courier New", monospace;
        color: #d8ffee;
        font-size: 14px;
    }

</style>
"""

st.markdown(CYBER_STYLE, unsafe_allow_html=True)

# -----------------------------
# HEADER
# -----------------------------
st.markdown("<div class='main-title'>🛡️ PayBuddy Security Toolkit</div>", unsafe_allow_html=True)
st.markdown("<div class='sub-title'>A unified toolkit for password checks, scanning, and reporting.</div>", unsafe_allow_html=True)

# -----------------------------
# SIDEBAR NAVIGATION (simple + clean)
# -----------------------------
st.sidebar.title("⚙️ Navigation")

section = st.sidebar.radio(
    "Select a module:",
    [
        "Identity & Consent",
        "Password Assessment",
        "Port Scan",
        "Footprinting",
        "HTTP Stress Test",
        "Packet Capture",
        "Summary Report",
    ]
)


# Helper to check identity + consent
def check_identity_consent():
    identity = read_file_content("../identity.txt")
    consent = read_file_content("../consent.txt")
    return identity, consent


# -----------------------------
# SECTION: IDENTITY & CONSENT
# -----------------------------
if section == "Identity & Consent":

    st.header("Identity & Consent Status")

    identity, consent = check_identity_consent()

    st.subheader("Identity File")
    st.markdown(f"<div class='terminal-box'>{identity or '❌ Missing identity.txt'}</div>", unsafe_allow_html=True)

    st.subheader("Consent File")
    st.markdown(f"<div class='terminal-box'>{consent or '❌ Missing consent.txt'}</div>", unsafe_allow_html=True)


# -----------------------------
# SECTION: PASSWORD ASSESSMENT
# -----------------------------
elif section == "Password Assessment":

    identity, consent = check_identity_consent()
    if not identity or not consent:
        st.error("Identity & consent required before using this module.")
        st.stop()

    st.header("Password Assessment")

    pwd = st.text_input("Enter password to test", type="password")

    if st.button("Analyze Password"):
        if not pwd:
            st.warning("Enter a password first.")
        else:
            result = password_assessment(pwd)
            st.markdown("<div class='terminal-box'>Password Result:</div>", unsafe_allow_html=True)
            st.json(result)

    if st.button("Run Weak Password Simulation"):
        sim = password_assessment("placeholder", simulate=True)
        st.markdown("<div class='terminal-box'>Weak Password Simulation:</div>", unsafe_allow_html=True)
        st.json(sim)


# -----------------------------
# SECTION: PORT SCAN
# -----------------------------
elif section == "Port Scan":

    identity, consent = check_identity_consent()
    if not identity or not consent:
        st.error("Identity & consent required before using this module.")
        st.stop()

    st.header("Port Scanner")

    target = st.text_input("Target Host", "127.0.0.1")
    start_port = st.number_input("Start Port", min_value=1, max_value=65535, value=70)
    end_port = st.number_input("End Port", min_value=1, max_value=65535, value=90)

    if st.button("Run Scan"):
        result = port_scan(target, start_port, end_port)
        st.json(result)


# -----------------------------
# SECTION: FOOTPRINTING
# -----------------------------
elif section == "Footprinting":

    identity, consent = check_identity_consent()
    if not identity or not consent:
        st.error("Identity & consent required before using this module.")
        st.stop()

    st.header("Footprinting")

    domain = st.text_input("Domain", "example.com")
    prefix = st.text_input("Evidence Prefix", "scan1")

    colA, colB = st.columns(2)

    with colA:
        if st.button("Enumerate Directories"):
            result = enumerate_directories(domain, prefix)
            st.json(result)

    with colB:
        if st.button("Enumerate Subdomains"):
            result = enumerate_subdomains(domain, prefix)
            st.json(result)


# -----------------------------
# SECTION: HTTP STRESS TEST
# -----------------------------
elif section == "HTTP Stress Test":

    identity, consent = check_identity_consent()
    if not identity or not consent:
        st.error("Identity & consent required before using this module.")
        st.stop()

    st.header("HTTP Stress Test")

    url = st.text_input("Target URL", "https://example.com")
    total_requests = st.number_input("Total Requests", 1, 500, 20)

    if st.button("Run Stress Test"):
        result = run_stress_test(url, total_requests)
        st.json(result)

        graph = result.get("graph")
        if graph and os.path.exists(graph):
            st.image(graph)


# -----------------------------
# SECTION: PACKET CAPTURE
# -----------------------------
elif section == "Packet Capture":

    identity, consent = check_identity_consent()
    if not identity or not consent:
        st.error("Identity & consent required before using this module.")
        st.stop()

    st.header("Packet Capture")

    count = st.number_input("Packets to Capture", 1, 300, 50)

    if st.button("Capture Packets"):
        result = run_packet_capture(count)
        st.json(result)


# -----------------------------
# SECTION: SUMMARY REPORT
# -----------------------------
elif section == "Summary Report":

    identity, consent = check_identity_consent()
    if not identity or not consent:
        st.error("Identity & consent required to generate report.")
        st.stop()

    st.header("Generate Summary Report")

    if st.button("Generate Report"):
        path = generate_report()

        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = f.read()

            st.text_area("Report Content", data, height=300)
            st.success(f"Report saved at: {path}")
        else:
            st.error("Failed to generate report.")

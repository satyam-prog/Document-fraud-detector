import hashlib
import io
import mimetypes
import os
import re
import sqlite3

import cv2
import fitz
import numpy as np
import pandas as pd
import pytesseract
import streamlit as st
from PIL import Image, ImageStat


st.set_page_config(
    page_title="Document Forgery Detection",
    page_icon="🕵️",
    layout="wide",
)


st.markdown(
    """
    <style>
        .stApp {
            background: linear-gradient(135deg, #0f172a, #111827 35%, #1f2937);
            color: #e5e7eb;
        }
        .stTitle, .stHeader, .stSubheader {
            color: #f8fafc;
        }
        .stDataFrame {
            background: rgba(15, 23, 42, 0.85);
            border-radius: 12px;
        }
        div[data-testid="stFileUploader"] > section {
            background: rgba(30, 41, 59, 0.7);
            border: 1px solid rgba(148, 163, 184, 0.3);
            border-radius: 12px;
        }
        .stTextArea textarea {
            background: rgba(15, 23, 42, 0.8);
            color: #f8fafc;
        }
        .block-container {
            padding-top: 2rem;
            padding-bottom: 3rem;
        }
        .metric-card {
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid rgba(148, 163, 184, 0.22);
            border-radius: 14px;
            padding: 1rem 1.2rem;
            box-shadow: 0 10px 20px rgba(15, 23, 42, 0.18);
        }
        .metric-title {
            font-size: 0.78rem;
            color: #a5b4fc;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 0.5rem;
        }
        .metric-value {
            font-size: 2rem;
            font-weight: 700;
            color: #f8fafc;
        }
        .metric-sub {
            font-size: 0.85rem;
            color: #cbd5e1;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


def get_basic_file_details(uploaded_file):
    file_name = uploaded_file.name
    file_size = uploaded_file.size
    file_type = uploaded_file.type or mimetypes.guess_type(file_name)[0] or "Unknown"

    return {
        "Filename": file_name,
        "Size (bytes)": file_size,
        "Type": file_type,
    }


def analyze_image_forensics(file_obj):
    uploaded_file = file_obj
    uploaded_file.seek(0)
    image = Image.open(uploaded_file)
    image_rgb = image.convert("RGB")
    arr = np.array(image_rgb)

    width, height = image.size
    stats = ImageStat.Stat(image_rgb)
    brightness = float(np.mean(stats.mean))
    contrast = float(np.std(arr))
    edge_density = float(np.abs(np.diff(arr.astype(np.float32), axis=0)).mean())

    return {
        "Width": width,
        "Height": height,
        "Mode": image.mode,
        "Mean brightness": round(brightness, 2),
        "Contrast score": round(contrast, 2),
        "Edge density": round(edge_density, 4),
    }


def extract_pdf_metadata(file_obj):
    file_obj.seek(0)
    pdf_bytes = file_obj.getvalue()
    pdf_doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    metadata = pdf_doc.metadata

    pdf_summary = {
        "Pages": pdf_doc.page_count,
        "Title": metadata.get("title") or "N/A",
        "Author": metadata.get("author") or "N/A",
        "Subject": metadata.get("subject") or "N/A",
        "Creator": metadata.get("creator") or "N/A",
        "Producer": metadata.get("producer") or "N/A",
        "Creation Date": metadata.get("creationDate") or "N/A",
        "Modification Date": metadata.get("modDate") or "N/A",
        "Encrypted": bool(metadata.get("encryption")) or pdf_doc.is_encrypted,
    }

    pdf_doc.close()
    return pdf_summary


def extract_pdf_text(file_obj):
    file_obj.seek(0)
    pdf_bytes = file_obj.read()

    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception as exc:
        return f"Unable to read PDF text: {exc}"

    extracted_pages = []
    for page in doc:
        page_text = page.get_text("text")
        if page_text.strip():
            extracted_pages.append(page_text)

    doc.close()
    combined_text = "\n\n".join(extracted_pages).strip()
    return combined_text if combined_text else "No readable text found in the PDF."


def extract_image_text(file_obj):
    file_obj.seek(0)
    image = Image.open(file_obj)
    image = image.convert("RGB")

    try:
        extracted_text = pytesseract.image_to_string(image)
    except Exception as exc:
        return f"OCR failed: {exc}"

    cleaned_text = extracted_text.strip()
    return cleaned_text if cleaned_text else "No readable text found in the image."


def find_regex_matches(text):
    patterns = {
        "Potential ID / Reference": r"\b(?:[A-Z]{2,5}[-\s]?\d{4,8}|[A-Z0-9]{6,12})\b",
        "Potential Date": r"\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4})\b",
    }

    matches = []
    for label, pattern in patterns.items():
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            matches.append({"Type": label, "Match": match.group(0)})

    return pd.DataFrame(matches, columns=["Type", "Match"]) if matches else pd.DataFrame(columns=["Type", "Match"])


def highlight_regex_matches(text):
    pattern = re.compile(
        r"\b(?:[A-Z]{2,5}[-\s]?\d{4,8}|[A-Z0-9]{6,12}|(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4}))\b",
        flags=re.IGNORECASE,
    )

    escaped_text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    highlighted = pattern.sub(lambda m: f"<mark>{m.group(0)}</mark>", escaped_text)
    return highlighted


def extract_image_exif(uploaded_file):
    uploaded_file.seek(0)
    image = Image.open(uploaded_file)
    exif_data = image.getexif()

    if not exif_data:
        return pd.DataFrame(columns=["Tag", "Value"])

    rows = []
    for key, value in exif_data.items():
        try:
            rows.append({"Tag": key, "Value": str(value)})
        except Exception:
            rows.append({"Tag": key, "Value": "Unprintable value"})

    df = pd.DataFrame(rows)
    return df


def compute_ela(uploaded_file, quality=95):
    uploaded_file.seek(0)
    image = Image.open(uploaded_file).convert("RGB")
    image_np = np.array(image)

    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", quality=quality)
    reloaded = Image.open(io.BytesIO(buffer.getvalue())).convert("RGB")
    reloaded_np = np.array(reloaded)

    diff = cv2.absdiff(image_np, reloaded_np)
    gray = cv2.cvtColor(diff, cv2.COLOR_RGB2GRAY)
    _, thresh = cv2.threshold(gray, 20, 255, cv2.THRESH_BINARY)
    heatmap = cv2.applyColorMap(thresh, cv2.COLORMAP_JET)

    return image, heatmap


def compute_sha256(file_obj):
    file_obj.seek(0)
    file_bytes = file_obj.read()
    return hashlib.sha256(file_bytes).hexdigest()


def setup_authentic_hash_db(db_path="authentic_hashes.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS authentic_hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT NOT NULL,
            hash_value TEXT NOT NULL
        )
        """
    )

    dummy_hashes = [
        ("sample_doc_001.pdf", "3d7e8f3b6b40d26a0db1d0b1176900d0100c166d61247d2e1d3d17d7b1d7f9d1"),
        ("sample_id_card.jpg", "9c7af7e6ea1601955c5b2ad5d9d182856455271ec7f9b9d30e56dcf6f0443d12"),
        ("sample_certificate.png", "b1d9a2ce48d4204b8a2e7ff7df2d917a8d028b25d3f516eb3a9b204f420b4d5f"),
    ]

    for file_name, hash_value in dummy_hashes:
        cursor.execute(
            "SELECT 1 FROM authentic_hashes WHERE file_name = ? AND hash_value = ?",
            (file_name, hash_value),
        )
        if not cursor.fetchone():
            cursor.execute(
                "INSERT INTO authentic_hashes (file_name, hash_value) VALUES (?, ?)",
                (file_name, hash_value),
            )

    conn.commit()
    conn.close()


def verify_uploaded_hash(file_hash, db_path="authentic_hashes.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT hash_value FROM authentic_hashes")
    stored_hashes = {row[0] for row in cursor.fetchall()}
    conn.close()
    return file_hash in stored_hashes


def calculate_overall_risk(uploaded_file, integrity_verified, exif_software_flag=False, forensic_data=None):
    score = 0
    if not integrity_verified:
        score += 60
    if exif_software_flag:
        score += 15
    if forensic_data is not None:
        if forensic_data.get("Contrast score", 0) > 80:
            score += 10
        if forensic_data.get("Edge density", 0) > 7:
            score += 10

    score = min(score, 100)

    if score < 25:
        label = "Low Risk"
    elif score < 60:
        label = "Monitor"
    elif score < 85:
        label = "High Risk"
    else:
        label = "Critical"

    return score, label


def render_verification_section(uploaded_file):
    sha256_hash = compute_sha256(uploaded_file)
    setup_authentic_hash_db()
    is_verified = verify_uploaded_hash(sha256_hash)

    st.subheader("Cryptographic Verification")
    st.code(f"SHA-256: {sha256_hash}", language="text")

    if is_verified:
        st.markdown(
            """
            <div style='background-color:#14532d; border:1px solid #22c55e; border-radius:12px; padding:24px; text-align:center; font-size:36px; font-weight:700; color:#dcfce7;'>
                VERIFIED
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.success("The uploaded file matches a stored authentic hash in the database.")
    else:
        st.markdown(
            """
            <div style='background-color:#7f1d1d; border:1px solid #ef4444; border-radius:12px; padding:24px; text-align:center; font-size:30px; font-weight:700; color:#fee2e2;'>
                TAMPERING DETECTED
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.error("The uploaded file does not match the authentic hashes stored in the database.")

    return is_verified


def render_summary_cards(uploaded_file, integrity_verified, exif_software_flag=False, forensic_data=None):
    risk_score, risk_label = calculate_overall_risk(
        uploaded_file,
        integrity_verified,
        exif_software_flag=exif_software_flag,
        forensic_data=forensic_data,
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">Integrity</div>
                <div class="metric-value">{'OK' if integrity_verified else 'Flagged'}</div>
                <div class="metric-sub">Hash verification status</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">Risk Score</div>
                <div class="metric-value">{risk_score}%</div>
                <div class="metric-sub">{risk_label}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">Visual Signals</div>
                <div class="metric-value">{ 'Detected' if exif_software_flag or (forensic_data and (forensic_data.get('Contrast score',0) > 80 or forensic_data.get('Edge density',0) > 7)) else 'Normal' }</div>
                <div class="metric-sub">Metadata & ELA analysis</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_image_section(uploaded_file):
    uploaded_file.seek(0)
    image = Image.open(uploaded_file)
    st.subheader("Document preview")
    st.image(image, caption=uploaded_file.name, use_container_width=True)

    st.subheader("Visual Forensics")
    exif_df = extract_image_exif(uploaded_file)
    exif_software_flag = False
    if exif_df.empty:
        st.info("No EXIF metadata found in this image.")
    else:
        st.dataframe(exif_df, use_container_width=True, hide_index=True)

        software_hits = exif_df[exif_df["Value"].str.contains("Adobe|Photoshop|GIMP|Lightroom|Canva", case=False, na=False)]
        if not software_hits.empty:
            exif_software_flag = True
            st.warning("EXIF metadata suggests the image was edited with software such as Adobe Photoshop or similar tools.")

    forensic_data = analyze_image_forensics(uploaded_file)
    render_summary_cards(
        uploaded_file,
        integrity_verified=True,
        exif_software_flag=exif_software_flag,
        forensic_data=forensic_data,
    )

    original_img, ela_heatmap = compute_ela(uploaded_file, quality=95)
    col1, col2 = st.columns(2)
    with col1:
        st.caption("Original image")
        st.image(original_img, use_container_width=True)
    with col2:
        st.caption("ELA heatmap")
        st.image(ela_heatmap, use_container_width=True)

    st.info("Areas with stronger ELA contrast may indicate digital tampering, splicing, or region-based editing.")

    st.subheader("Image forensic indicators")
    st.dataframe(pd.DataFrame([forensic_data]), use_container_width=True, hide_index=True)

    risk_flags = []
    if forensic_data["Contrast score"] > 80:
        risk_flags.append("High contrast may indicate local enhancement or manipulation.")
    if forensic_data["Edge density"] > 7:
        risk_flags.append("Unusually high edge activity may suggest artifact injection or tampering.")

    if risk_flags:
        st.warning("Possible forgery indicators detected")
        for item in risk_flags:
            st.write("- " + item)
    else:
        st.success("No obvious visual anomalies detected from the basic inspection metrics.")

    extracted_text = extract_image_text(uploaded_file)
    st.subheader("Extracted Data")
    st.text_area("Extracted text", value=extracted_text, height=260, disabled=True)

    st.subheader("Detected ID / Date Matches")
    matches_df = find_regex_matches(extracted_text)
    if matches_df.empty:
        st.info("No obvious ID numbers or dates were detected in the extracted text.")
    else:
        st.dataframe(matches_df, use_container_width=True, hide_index=True)

    st.markdown("### Highlighted Matches")
    st.markdown(highlight_regex_matches(extracted_text), unsafe_allow_html=True)


def render_pdf_section(uploaded_file):
    st.subheader("PDF metadata overview")
    pdf_data = extract_pdf_metadata(uploaded_file)
    st.dataframe(pd.DataFrame([pdf_data]), use_container_width=True, hide_index=True)

    extracted_text = extract_pdf_text(uploaded_file)
    st.subheader("Extracted Data")
    st.text_area("Extracted text", value=extracted_text, height=260, disabled=True)

    st.subheader("Detected ID / Date Matches")
    matches_df = find_regex_matches(extracted_text)
    if matches_df.empty:
        st.info("No obvious ID numbers or dates were detected in the extracted text.")
    else:
        st.dataframe(matches_df, use_container_width=True, hide_index=True)

    st.markdown("### Highlighted Matches")
    st.markdown(highlight_regex_matches(extracted_text), unsafe_allow_html=True)


with st.sidebar:
    st.title("Navigation")
    st.radio(
        "Sections",
        ["Dashboard", "Upload & Inspect", "Forensic Results"],
        index=1,
    )

    st.markdown("---")
    st.caption("Forged document investigation pipeline")
    st.write("Inspect suspicious files for visual anomalies, metadata inconsistencies, and document manipulation traces.")


st.title("Document Forgery Detection")
st.caption("Analyze uploaded PDFs, JPGs, and PNGs for suspicious characteristics.")

uploaded_file = st.file_uploader(
    "Upload a document for inspection",
    type=["pdf", "jpg", "jpeg", "png"],
    help="Supported formats: PDF, JPG, PNG",
)

if uploaded_file is not None:
    basic_details = get_basic_file_details(uploaded_file)

    st.subheader("File details")
    st.dataframe(pd.DataFrame([basic_details]), use_container_width=True, hide_index=True)

    integrity_verified = render_verification_section(uploaded_file)

    lower_name = uploaded_file.name.lower()

    if lower_name.endswith((".jpg", ".jpeg", ".png")):
        render_image_section(uploaded_file)
    elif lower_name.endswith(".pdf"):
        render_pdf_section(uploaded_file)
    else:
        st.warning("Unsupported file type.")

    if lower_name.endswith((".jpg", ".jpeg", ".png")):
        forensic_data = analyze_image_forensics(uploaded_file)
        exif_df = extract_image_exif(uploaded_file)
        exif_software_flag = not exif_df.empty and not exif_df[exif_df["Value"].str.contains("Adobe|Photoshop|GIMP|Lightroom|Canva", case=False, na=False)].empty
        render_summary_cards(uploaded_file, integrity_verified, exif_software_flag=exif_software_flag, forensic_data=forensic_data)

"""Cornea-Guard — Streamlit Community Cloud Dashboard.

Reuses the exact same zero-SSRF URL phishing engine and zero-knowledge password
hygiene modules from ``core/`` with full English / Hindi accessibility.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import streamlit as st

from core.password_analyzer import analyze_password, generate_secure_password
from core.url_analyzer import analyze_url
from core.validators import (
    MAX_PASSWORD_LENGTH,
    MAX_URL_LENGTH,
    ValidationError,
    validate_password_input,
    validate_url_input,
)

st.set_page_config(
    page_title="Cornea-Guard — Phishing & Credential Hygiene Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

DEMO_PRESETS: dict[str, tuple[str, str]] = {
    "fake_sbi": ("url", "http://sbi-kyc-urgent-verify.xyz/login?otp=confirm"),
    "safe_link": ("url", "https://www.onlinesbi.sbi/personal/index.html"),
    "weak_pw": ("password", "Password1234!"),
    "strong_pw": ("password", "C0rnea#Sh1eld!94$Vortex_Kite"),
}

UI_TEXT: dict[str, dict[str, str]] = {
    "en": {
        "title": "🛡️ Cornea-Guard",
        "subtitle": "Real-Time Phishing & Credential Hygiene Shield • Zero-Storage • Zero-SSRF",
        "presets_heading": "Instant Real-World Demo Presets",
        "preset_fake_sbi": "✕ Fake SBI KYC Link",
        "preset_safe_link": "✓ Safe Official Link",
        "preset_weak_pw": "⚠ Weak Password",
        "preset_strong_pw": "✓ Strong Passphrase",
        "url_tab": "🔗 Phishing Link Inspector",
        "pw_tab": "🔐 Zero-Knowledge Password Shield",
        "url_label": "Paste any SMS, WhatsApp, banking, UPI, or delivery URL (never visited)",
        "url_placeholder": "https://example.com or http://sbi-kyc-verify.xyz/login",
        "url_btn": "Inspect Link",
        "pw_label": "Enter password to audit (never logged or stored)",
        "pw_placeholder": "Enter or generate a password...",
        "pw_btn": "Audit Password",
        "gen_heading": "1-Click Cryptographic Password Generator (Python secrets)",
        "gen_length": "Password length",
        "gen_btn": "⚡ Generate Strong Password",
        "verdict_heading": "Live Security Verdict",
        "score_label": "Safety Score",
        "risk_label": "Risk Level",
        "latency_label": "Scan Latency",
        "findings_heading": "Diagnostic Findings & Explanations",
        "analytics_heading": "Real-Time Session Analytics",
        "log_heading": "Recent Scan Log (Passwords Always Masked)",
        "clear_log": "Clear Log",
        "empty_verdict": "Run a URL scan, password audit, or click a demo preset above to begin.",
        "empty_log": "No scans recorded in this session yet.",
        "crack_time": "Est. Crack Time",
        "entropy": "Shannon Entropy",
        "pool": "Char Pool Size",
        "length": "Length",
        "masked_pw": "•••••••• (Password Audit — Never Stored)",
    },
    "hi": {
        "title": "🛡️ कॉर्निया-गार्ड (Cornea-Guard)",
        "subtitle": "रियल-टाइम फ़िशिंग और पासवर्ड सुरक्षा कवच • ज़ीरो-स्टोरेज • ज़ीरो-SSRF",
        "presets_heading": "त्वरित लाइव डेमो प्रीसेट",
        "preset_fake_sbi": "✕ नकली SBI KYC लिंक",
        "preset_safe_link": "✓ सुरक्षित आधिकारिक लिंक",
        "preset_weak_pw": "⚠ कमज़ोर पासवर्ड",
        "preset_strong_pw": "✓ मजबूत पासफ़्रेज़",
        "url_tab": "🔗 फ़िशिंग लिंक निरीक्षक",
        "pw_tab": "🔐 ज़ीरो-नॉलेज पासवर्ड सुरक्षा कवच",
        "url_label": "कोई भी SMS, WhatsApp, बैंकिंग या UPI लिंक पेस्ट करें (लिंक कभी खोला नहीं जाता)",
        "url_placeholder": "https://example.com या http://sbi-kyc-verify.xyz/login",
        "url_btn": "लिंक जांचें",
        "pw_label": "जांच के लिए पासवर्ड दर्ज करें (कभी सेव नहीं होता)",
        "pw_placeholder": "पासवर्ड लिखें या नया बनाएं...",
        "pw_btn": "पासवर्ड जांचें",
        "gen_heading": "1-क्लिक सुरक्षित पासवर्ड जनरेटर (Python secrets)",
        "gen_length": "पासवर्ड की लंबाई",
        "gen_btn": "⚡ मजबूत पासवर्ड बनाएं",
        "verdict_heading": "लाइव सुरक्षा परिणाम",
        "score_label": "सुरक्षा स्कोर",
        "risk_label": "जोखिम स्तर",
        "latency_label": "जांच समय",
        "findings_heading": "विस्तृत सुरक्षा निष्कर्ष और कारण",
        "analytics_heading": "रियल-टाइम सत्र विश्लेषण",
        "log_heading": "हाल की जांच सूची (पासवर्ड हमेशा छिपाए जाते हैं)",
        "clear_log": "सूची साफ़ करें",
        "empty_verdict": "शुरू करने के लिए कोई लिंक या पासवर्ड जांचें, या ऊपर डेमो बटन पर क्लिक करें।",
        "empty_log": "इस सत्र में अभी तक कोई जांच दर्ज नहीं हुई है।",
        "crack_time": "अनुमानित क्रैक समय",
        "entropy": "शैनन एन्ट्रॉपी",
        "pool": "अक्षर पूल आकार",
        "length": "लंबाई",
        "masked_pw": "•••••••• (पासवर्ड जांच — कभी सेव नहीं)",
    },
}


def _init_session_state() -> None:
    """Initialize in-memory Streamlit session keys cleanly."""
    defaults: dict[str, Any] = {
        "lang": "en",
        "url_value": "",
        "pw_value": "",
        "last_scan_type": None,
        "last_result": None,
        "generated_password": "",
        "stats": {"Safe": 0, "Suspicious": 0, "High Risk": 0},
        "history": [],
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def _record_result(scan_type: str, result: dict[str, Any], target_label: str) -> None:
    """Store latest verdict and update session analytics without saving passwords."""
    st.session_state.last_scan_type = scan_type
    st.session_state.last_result = result
    level: str = result["risk_level"]
    if level in st.session_state.stats:
        st.session_state.stats[level] += 1

    st.session_state.history.insert(
        0,
        {
            "scan_type": scan_type,
            "target": target_label,
            "score": result["safety_score"],
            "risk_level": level,
            "risk_icon": result["risk_icon"],
            "latency_ms": result["scan_time_ms"],
            "time": datetime.now().strftime("%H:%M:%S"),
        },
    )
    st.session_state.history = st.session_state.history[:12]


def _run_url_scan(raw_url: str) -> None:
    """Validate and execute static phishing inspection."""
    try:
        validated: str = validate_url_input(raw_url)
    except ValidationError as exc:
        st.error(f"✕ {exc.message}")
        return
    report: dict[str, Any] = analyze_url(validated)
    _record_result("url", report, validated)


def _run_password_audit(raw_password: str) -> None:
    """Validate and execute zero-knowledge password audit."""
    try:
        validated: str = validate_password_input(raw_password)
    except ValidationError as exc:
        st.error(f"✕ {exc.message}")
        return
    report: dict[str, Any] = analyze_password(validated)
    _record_result("password", report, "MASKED")


def main() -> None:
    """Render the Cornea-Guard Streamlit application."""
    _init_session_state()

    header_col, lang_col = st.columns([5, 1])
    with lang_col:
        selected_lang = st.radio(
            "Language",
            options=["en", "hi"],
            format_func=lambda code: "English" if code == "en" else "हिन्दी",
            horizontal=True,
            label_visibility="collapsed",
            key="lang",
        )

    txt: dict[str, str] = UI_TEXT[selected_lang]

    with header_col:
        st.title(txt["title"])
        st.caption(txt["subtitle"])

    # One-Click Demo Presets Bar
    st.subheader(txt["presets_heading"])
    p_cols = st.columns(4)
    preset_buttons: list[tuple[str, str]] = [
        ("fake_sbi", txt["preset_fake_sbi"]),
        ("safe_link", txt["preset_safe_link"]),
        ("weak_pw", txt["preset_weak_pw"]),
        ("strong_pw", txt["preset_strong_pw"]),
    ]
    for col, (preset_key, label) in zip(p_cols, preset_buttons):
        if col.button(label, use_container_width=True, key=f"btn_{preset_key}"):
            kind, value = DEMO_PRESETS[preset_key]
            if kind == "url":
                st.session_state.url_value = value
                _run_url_scan(value)
            else:
                st.session_state.pw_value = value
                _run_password_audit(value)

    st.divider()

    left_col, right_col = st.columns([7, 5], gap="large")

    # Left Column: Scanners
    with left_col:
        st.subheader(txt["url_tab"])
        with st.form("url_scan_form", clear_on_submit=False):
            url_input: str = st.text_input(
                txt["url_label"],
                value=st.session_state.url_value,
                max_chars=MAX_URL_LENGTH,
                placeholder=txt["url_placeholder"],
            )
            if st.form_submit_button(txt["url_btn"], type="primary", use_container_width=True):
                st.session_state.url_value = url_input
                _run_url_scan(url_input)

        st.markdown("---")

        st.subheader(txt["pw_tab"])
        with st.form("pw_scan_form", clear_on_submit=False):
            pw_input: str = st.text_input(
                txt["pw_label"],
                value=st.session_state.pw_value,
                max_chars=MAX_PASSWORD_LENGTH,
                type="password",
                placeholder=txt["pw_placeholder"],
            )
            if st.form_submit_button(txt["pw_btn"], type="primary", use_container_width=True):
                st.session_state.pw_value = pw_input
                _run_password_audit(pw_input)

        with st.container(border=True):
            st.markdown(f"**{txt['gen_heading']}**")
            gen_len: int = st.slider(txt["gen_length"], min_value=12, max_value=64, value=20)
            if st.button(txt["gen_btn"], use_container_width=True):
                generated: dict[str, Any] = generate_secure_password(length=gen_len)
                st.session_state.generated_password = generated["password"]
                st.session_state.pw_value = generated["password"]
                _run_password_audit(generated["password"])

            if st.session_state.generated_password:
                st.code(st.session_state.generated_password, language=None)

    # Right Column: Verdict, Findings, Analytics, History
    with right_col:
        st.subheader(txt["verdict_heading"])
        result: dict[str, Any] | None = st.session_state.last_result
        scan_type: str | None = st.session_state.last_scan_type

        if result is None:
            st.info(txt["empty_verdict"])
        else:
            score: int = int(result["safety_score"])
            risk_level: str = result["risk_level"]
            icon: str = result["risk_icon"]
            guidance: str = (
                result["action_guidance_hi"]
                if selected_lang == "hi"
                else result["action_guidance"]
            )

            m1, m2, m3 = st.columns(3)
            m1.metric(txt["score_label"], f"{score} / 100")
            m2.metric(txt["risk_label"], f"{icon} {risk_level}")
            m3.metric(txt["latency_label"], f"{result['scan_time_ms']:.2f} ms")
            st.progress(score / 100.0)

            if risk_level == "Safe":
                st.success(f"{icon} {guidance}")
            elif risk_level == "Suspicious":
                st.warning(f"{icon} {guidance}")
            else:
                st.error(f"{icon} {guidance}")

            if scan_type == "password":
                pm1, pm2 = st.columns(2)
                crack_val: str = (
                    result["crack_time_hi"]
                    if selected_lang == "hi"
                    else result["crack_time"]
                )
                pm1.metric(txt["crack_time"], crack_val)
                pm2.metric(txt["entropy"], f"{result['shannon_entropy_bits']} bits")
                pm3, pm4 = st.columns(2)
                pm3.metric(txt["pool"], str(result["character_pool_size"]))
                pm4.metric(txt["length"], str(result["length"]))

            st.markdown(f"**{txt['findings_heading']}**")
            for item in result["findings"]:
                f_title: str = (
                    item["title_hi"] if selected_lang == "hi" else item["title"]
                )
                f_detail: str = (
                    item["detail_hi"] if selected_lang == "hi" else item["detail"]
                )
                sev: str = item.get("severity", "medium")
                line: str = f"**{item['icon']} {f_title}** — {f_detail}"
                if sev == "high":
                    st.error(line)
                elif sev == "safe":
                    st.success(line)
                else:
                    st.warning(line)

        st.markdown("---")
        st.subheader(txt["analytics_heading"])
        st.bar_chart(st.session_state.stats)

        log_header, clear_col = st.columns([3, 1])
        log_header.markdown(f"**{txt['log_heading']}**")
        if clear_col.button(txt["clear_log"]):
            st.session_state.history = []
            st.rerun()

        if not st.session_state.history:
            st.caption(txt["empty_log"])
        else:
            for entry in st.session_state.history:
                display_target: str = (
                    txt["masked_pw"]
                    if entry["scan_type"] == "password"
                    else entry["target"]
                )
                st.caption(
                    f"`{entry['time']}` • **{entry['risk_icon']} {entry['risk_level']} ({entry['score']}/100)** "
                    f"• `{entry['latency_ms']:.2f} ms` — `{display_target}`"
                )


if __name__ == "__main__":
    main()

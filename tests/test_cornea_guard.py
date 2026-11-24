"""Comprehensive automated test suite for Cornea-Guard.

Verifies phishing URL heuristics, zero-knowledge password analysis, CSPRNG
generation, security boundaries, HTTP security headers, and sub-50ms latency.
"""

from __future__ import annotations

import time
from typing import Any

import pytest
from flask.testing import FlaskClient

from app import create_app
from core.password_analyzer import analyze_password, generate_secure_password
from core.url_analyzer import analyze_url


@pytest.fixture()
def client() -> FlaskClient:
    """Provide an isolated Flask test client for each test case."""
    application = create_app()
    application.config["TESTING"] = True
    return application.test_client()


# ---------------------------------------------------------------------------
# 1. URL Phishing Inspector Tests (Safe vs. Phishing Indicators)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "safe_url",
    [
        "https://www.onlinesbi.sbi/personal/index.html",
        "https://www.hdfcbank.com/personal/ways-to-bank",
        "https://www.paypal.com/signin",
        "https://www.amazon.in/dp/B09G9BL5CP",
        "https://github.com/pallets/flask",
    ],
)
def test_safe_https_urls_score_safe(client: FlaskClient, safe_url: str) -> None:
    """Legitimate HTTPS official domains must receive a Safe verdict."""
    response = client.post("/api/scan-url", json={"url": safe_url})
    assert response.status_code == 200

    data: dict[str, Any] = response.get_json()
    assert data["risk_level"] == "Safe"
    assert data["safety_score"] >= 75
    assert data["parsed"]["has_https"] is True
    assert data["risk_icon"] == "✓"
    assert isinstance(data["reasons"], list) and len(data["reasons"]) >= 1
    assert data["scan_time_ms"] < 50.0


def test_raw_ip_address_phishing_url_detected(client: FlaskClient) -> None:
    """URLs using raw IPv4 hostnames without HTTPS must be flagged High Risk."""
    response = client.post(
        "/api/scan-url",
        json={"url": "http://192.168.10.45/sbi/verify-kyc"},
    )
    assert response.status_code == 200

    data: dict[str, Any] = response.get_json()
    finding_ids: set[str] = {item["id"] for item in data["findings"]}
    assert "RAW_IP_ADDRESS" in finding_ids
    assert "MISSING_HTTPS" in finding_ids
    assert "URGENCY_KEYWORDS" in finding_ids
    assert data["risk_level"] == "High Risk"
    assert data["safety_score"] < 40


@pytest.mark.parametrize(
    ("phishing_url", "expected_finding"),
    [
        ("http://sbi-kyc-urgent-verify.xyz/login?otp=confirm", "BRAND_IMPERSONATION"),
        ("https://paypa1-account-verify.top/signin", "BRAND_TYPOSQUATTING"),
        ("http://hdfc-alert-kyc.click/suspend", "BRAND_IMPERSONATION"),
        ("https://amaz0n-winner-prize.tk/claim", "BRAND_TYPOSQUATTING"),
    ],
)
def test_typosquatting_and_brand_spoofing_urls_flagged(
    client: FlaskClient,
    phishing_url: str,
    expected_finding: str,
) -> None:
    """Lookalike banking/e-commerce phishing domains must score High Risk."""
    response = client.post("/api/scan-url", json={"url": phishing_url})
    assert response.status_code == 200

    data: dict[str, Any] = response.get_json()
    finding_ids: set[str] = {item["id"] for item in data["findings"]}
    assert expected_finding in finding_ids
    assert "SUSPICIOUS_TLD" in finding_ids
    assert data["risk_level"] == "High Risk"
    assert data["safety_score"] < 40
    assert data["risk_icon"] == "✕"


def test_at_symbol_redirection_and_excessive_subdomains_flagged(
    client: FlaskClient,
) -> None:
    """'@' userinfo redirection tricks and deep subdomain chains must be caught."""
    tricky_url = (
        "https://www.sbi.co.in@login.secure.verify.account.evil-portal-kyc.xyz/free"
    )
    response = client.post("/api/scan-url", json={"url": tricky_url})
    assert response.status_code == 200

    data: dict[str, Any] = response.get_json()
    finding_ids: set[str] = {item["id"] for item in data["findings"]}
    assert "AT_SYMBOL_REDIRECT" in finding_ids
    assert "EXCESSIVE_SUBDOMAINS" in finding_ids
    assert "EXCESSIVE_HYPHENS" in finding_ids
    assert "SUSPICIOUS_TLD" in finding_ids
    assert data["risk_level"] == "High Risk"


def test_dangerous_javascript_scheme_blocked_as_high_risk(client: FlaskClient) -> None:
    """Executable javascript: URIs must be flagged immediately as High Risk."""
    response = client.post(
        "/api/scan-url",
        json={"url": "javascript:alert(document.cookie)"},
    )
    assert response.status_code == 200
    data: dict[str, Any] = response.get_json()
    finding_ids: set[str] = {item["id"] for item in data["findings"]}
    assert "DANGEROUS_SCHEME" in finding_ids
    assert data["risk_level"] == "High Risk"


# ---------------------------------------------------------------------------
# 2. Password Hygiene, Zero-Knowledge Privacy & Generator Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "weak_password",
    [
        "1234",
        "password",
        "qwerty",
        "Password1234!",
        "aaaaaa111111",
    ],
)
def test_weak_and_pattern_passwords_flagged_high_risk(
    client: FlaskClient,
    weak_password: str,
) -> None:
    """Weak, common, sequential, or repeated passwords must score High Risk."""
    response = client.post("/api/check-password", json={"password": weak_password})
    assert response.status_code == 200

    data: dict[str, Any] = response.get_json()
    assert "password" not in data
    assert data["risk_level"] == "High Risk"
    assert data["safety_score"] < 40
    assert data["crack_time"] == "Instantly"
    assert data["zero_knowledge_verified"] is True
    assert len(data["findings"]) >= 1


def test_zero_knowledge_never_echoes_raw_password(client: FlaskClient) -> None:
    """API response must never contain the raw submitted password string."""
    sentinel_passwords = [
        "CorneaUniqueToken_9981!",
        "MySecretPass1234_Alpha",
    ]
    for secret_value in sentinel_passwords:
        response = client.post("/api/check-password", json={"password": secret_value})
        assert response.status_code == 200
        assert secret_value not in response.get_data(as_text=True)
        assert "password" not in response.get_json()


def test_strong_high_entropy_password_scores_safe(client: FlaskClient) -> None:
    """High-entropy diverse passphrases must score Safe with long crack times."""
    secret_passphrase = "C0rnea#Sh1eld!94$Vortex_Kite"
    response = client.post(
        "/api/check-password",
        json={"password": secret_passphrase},
    )
    assert response.status_code == 200

    # Zero-knowledge privacy check: raw password never appears in response.
    assert secret_passphrase not in response.get_data(as_text=True)

    data: dict[str, Any] = response.get_json()
    assert data["risk_level"] == "Safe"
    assert data["safety_score"] >= 85
    assert data["shannon_entropy_bits"] > 80.0
    assert data["effective_entropy_bits"] > 80.0
    assert "Year" in data["crack_time"]
    assert all(data["character_classes"].values())


def test_cryptographic_password_generator_produces_unique_strong_passwords(
    client: FlaskClient,
) -> None:
    """GET /api/generate-password must return unique, diverse, high-entropy passwords."""
    res_one = client.get("/api/generate-password?length=24")
    res_two = client.get("/api/generate-password?length=24")
    assert res_one.status_code == 200
    assert res_two.status_code == 200

    data_one: dict[str, Any] = res_one.get_json()
    data_two: dict[str, Any] = res_two.get_json()

    assert data_one["length"] == 24
    assert len(data_one["password"]) == 24
    assert data_one["password"] != data_two["password"]
    assert data_one["risk_level"] == "Safe"
    assert data_one["safety_score"] >= 85
    assert "Year" in data_one["crack_time"]


# ---------------------------------------------------------------------------
# 3. Edge Cases, Input Validation & Security Boundary Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_payload",
    [
        {},
        {"url": ""},
        {"url": "    "},
        {"url": 12345},
        {"url": None},
        {"url": "https://example.com/\x00nullbyte"},
    ],
)
def test_scan_url_rejects_invalid_inputs(
    client: FlaskClient,
    bad_payload: dict[str, Any],
) -> None:
    """Malformed, empty, or non-string URL payloads must return clean JSON 400."""
    response = client.post("/api/scan-url", json=bad_payload)
    assert response.status_code == 400
    data: dict[str, Any] = response.get_json()
    assert "error" in data and "code" in data
    assert "Traceback" not in response.get_data(as_text=True)


def test_oversized_url_and_password_rejected(client: FlaskClient) -> None:
    """URLs > 2048 chars and passwords > 128 chars must be rejected with 400."""
    oversized_url = "https://example.com/" + ("a" * 2040)
    url_res = client.post("/api/scan-url", json={"url": oversized_url})
    assert url_res.status_code == 400
    assert url_res.get_json()["code"] == "URL_TOO_LONG"

    oversized_password = "X" * 129
    pw_res = client.post("/api/check-password", json={"password": oversized_password})
    assert pw_res.status_code == 400
    assert pw_res.get_json()["code"] == "PASSWORD_TOO_LONG"


def test_empty_and_invalid_password_inputs_rejected(client: FlaskClient) -> None:
    """Empty or non-string passwords must return structured JSON 400 errors."""
    for payload in [{}, {"password": ""}, {"password": 9999}, {"password": ["a"]}]:
        res = client.post("/api/check-password", json=payload)
        assert res.status_code == 400
        assert "error" in res.get_json()


def test_invalid_generator_length_rejected(client: FlaskClient) -> None:
    """Out-of-bounds or non-numeric generator length params must return 400."""
    for bad_query in ["?length=4", "?length=100", "?length=abc"]:
        res = client.get(f"/api/generate-password{bad_query}")
        assert res.status_code == 400
        assert "error" in res.get_json()


def test_xss_script_injection_is_sanitized(client: FlaskClient) -> None:
    """XSS script payloads inside URLs must be HTML-escaped in JSON output."""
    xss_url = "https://example.com/search?q=<script>alert('xss')</script>"
    response = client.post("/api/scan-url", json={"url": xss_url})
    assert response.status_code == 200

    raw_body: str = response.get_data(as_text=True)
    assert "<script>" not in raw_body
    assert "</script>" not in raw_body

    data: dict[str, Any] = response.get_json()
    assert "&lt;script&gt;" in data["url_sanitized"]
    finding_ids: set[str] = {item["id"] for item in data["findings"]}
    assert "SUSPICIOUS_HTML_CHARS" in finding_ids


def test_malformed_json_and_invalid_http_methods(client: FlaskClient) -> None:
    """Malformed JSON returns 400 and unsupported HTTP methods return JSON 405."""
    bad_json_res = client.post(
        "/api/scan-url",
        data="{not-valid-json",
        content_type="application/json",
    )
    assert bad_json_res.status_code == 400
    assert bad_json_res.get_json()["code"] == "MALFORMED_JSON"

    for method_call in [
        client.get("/api/scan-url"),
        client.delete("/api/check-password"),
        client.post("/api/generate-password"),
    ]:
        assert method_call.status_code == 405
        assert method_call.get_json()["code"] == "METHOD_NOT_ALLOWED"
        assert "Traceback" not in method_call.get_data(as_text=True)

    not_found_res = client.get("/api/does-not-exist")
    assert not_found_res.status_code == 404
    assert not_found_res.get_json()["code"] == "NOT_FOUND"


# ---------------------------------------------------------------------------
# 4. HTTP Security Headers & Dashboard Accessibility Tests
# ---------------------------------------------------------------------------


def test_security_headers_present_on_dashboard_and_api(client: FlaskClient) -> None:
    """All responses must enforce CSP, X-Frame-Options, nosniff, and no-referrer."""
    page_res = client.get("/")
    assert page_res.status_code == 200

    api_res = client.post("/api/scan-url", json={"url": "https://www.onlinesbi.sbi"})
    assert api_res.status_code == 200

    for res in (page_res, api_res):
        assert "Content-Security-Policy" in res.headers
        assert "default-src 'self'" in res.headers["Content-Security-Policy"]
        assert res.headers.get("X-Content-Type-Options") == "nosniff"
        assert res.headers.get("X-Frame-Options") == "DENY"
        assert res.headers.get("Referrer-Policy") == "no-referrer"

    assert "no-store" in api_res.headers.get("Cache-Control", "")


def test_dashboard_includes_accessibility_and_demo_presets(client: FlaskClient) -> None:
    """HTML dashboard must expose semantic landmarks, ARIA live regions, and presets."""
    html_body: str = client.get("/").get_data(as_text=True)
    for required_marker in (
        "<header",
        "<main",
        "<section",
        'aria-live="polite"',
        'id="lang-hi-btn"',
        'data-preset="fake-sbi"',
        'data-preset="safe-link"',
        'data-preset="weak-password"',
        'data-preset="strong-password"',
    ):
        assert required_marker in html_body


# ---------------------------------------------------------------------------
# 5. Sub-50ms Performance & Efficiency Tests
# ---------------------------------------------------------------------------


def test_url_and_password_analysis_performance_under_50ms(client: FlaskClient) -> None:
    """Both pure functions and full API roundtrips must complete in under 50ms."""
    complex_url = (
        "http://sbi.co.in@secure.login.verify.account.sbi-kyc-urgent-alert.xyz:8080"
        "/update/kyc/confirm?otp=1234&winner=free&redirect=%2Flogin%2Fauth%2Fverify%2Fnow"
    )
    complex_pw = "Tr0ub4dor&3!_CorneaGuard#Shield99_Vortex"

    # Direct pure-function timing.
    t0 = time.perf_counter()
    url_report = analyze_url(complex_url)
    url_wall_ms = (time.perf_counter() - t0) * 1000.0
    assert url_report["scan_time_ms"] < 50.0
    assert url_wall_ms < 50.0

    t1 = time.perf_counter()
    pw_report = analyze_password(complex_pw)
    pw_wall_ms = (time.perf_counter() - t1) * 1000.0
    assert pw_report["scan_time_ms"] < 50.0
    assert pw_wall_ms < 50.0

    t2 = time.perf_counter()
    gen_report = generate_secure_password(32)
    gen_wall_ms = (time.perf_counter() - t2) * 1000.0
    assert gen_report["scan_time_ms"] < 50.0
    assert gen_wall_ms < 50.0

    # End-to-end Flask API client timing.
    api_t0 = time.perf_counter()
    api_url_res = client.post("/api/scan-url", json={"url": complex_url})
    api_url_ms = (time.perf_counter() - api_t0) * 1000.0
    assert api_url_res.status_code == 200
    assert api_url_res.get_json()["scan_time_ms"] < 50.0
    assert api_url_ms < 50.0

    api_t1 = time.perf_counter()
    api_pw_res = client.post("/api/check-password", json={"password": complex_pw})
    api_pw_ms = (time.perf_counter() - api_t1) * 1000.0
    assert api_pw_res.status_code == 200
    assert api_pw_res.get_json()["scan_time_ms"] < 50.0
    assert api_pw_ms < 50.0

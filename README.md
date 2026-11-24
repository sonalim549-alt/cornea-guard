# Cornea-Guard — Real-Time Phishing & Credential Hygiene Shield

A lightweight, production-grade cybersecurity web application built with **Python (Flask)** and a responsive **Tailwind CSS** dark-mode dashboard. Designed to protect everyday users against lookalike phishing scams (fake banking, UPI, KYC, and delivery links) and weak, easily crackable passwords with **sub-10ms** execution, **zero-storage password privacy**, **zero-SSRF static URL inspection**, and **WCAG 2.1 AA** accessibility (including live English / हिन्दी translation).

---

## Key Features

### 1. Static Phishing Link Inspector (`POST /api/scan-url`)
Evaluates any pasted URL purely via static lexical and structural inspection **without ever visiting, resolving, or executing it** (zero SSRF risk):
- **Missing HTTPS Detection:** Flags unencrypted `http://` or scheme-less links.
- **Raw IP Address Detection:** Catches IPv4, IPv6, and numeric/hex obfuscated IP hostnames.
- **Brand Impersonation & Typosquatting:** Detects unauthorized use or homoglyph/edit-distance spoofing of banking, UPI, government, e-commerce, and delivery brands (e.g., `sbi-kyc`, `paypa1`, `hdfc-alert`, `amaz0n`, `paytm`, `phonepe`, `uidai`, `dhl`).
- **High-Risk TLDs & Shorteners:** Flags disposable/abused extensions (`.xyz`, `.top`, `.tk`, `.click`, etc.) and URL shorteners (`bit.ly`, `tinyurl.com`, etc.).
- **Structural Tricks:** Detects `@` userinfo redirection tricks, Punycode (`xn--`), excessive subdomains/hyphens, non-standard ports, heavy percent-encoding, dangerous schemes (`javascript:`, `data:`), and XSS markup characters.
- **Urgency Lure Keywords:** Identifies social-engineering pressure words (`verify`, `urgent`, `kyc`, `suspend`, `winner`, `free`, `otp`, `blocked`, etc.).
- **Clear Verdict:** Returns a **Safety Score (0–100)**, Risk Level (`Safe`, `Suspicious`, `High Risk`), color-blind safe icons (`✓`, `⚠`, `✕`), plain-language English & Hindi explanations, and exact `scan_time_ms`.

### 2. Zero-Knowledge Password Hygiene & CSPRNG Generator (`POST /api/check-password`, `GET /api/generate-password`)
- **Zero-Storage Privacy:** Raw passwords are never logged, persisted, cached (`Cache-Control: no-store`), or echoed back in API responses.
- **Entropy & Pattern Analysis:** Computes true **Shannon entropy**, character pool diversity (`a-z`, `A-Z`, `0-9`, symbols), and deducts penalties for breached/dictionary words (including leetspeak variants), keyboard/numeric sequences (`1234`, `qwerty`, `abcd`), repeated characters/chunks, and calendar years.
- **Realistic Crack-Time Estimation:** Estimates offline GPU cracking time (at 10 billion guesses/second) from `"Instantly"` to `"Billions of Years"` in both English and Hindi.
- **1-Click Secure Password Generator:** Generates cryptographically random passwords (12–64 chars) exclusively using Python's `secrets` module with guaranteed 4-class diversity.

### 3. Live Interactive Threat Dashboard & WCAG 2.1 AA Accessibility
- **Dynamic SVG Risk Gauge** with animated score arc and sub-10ms latency badge.
- **Real-Time Session Analytics** doughnut chart (Chart.js) and masked Recent Scan Log.
- **4 One-Click Demo Presets:** *Fake SBI KYC Link*, *Safe Official Link*, *Weak Password*, and *Strong Passphrase*.
- **Bilingual Toggle (English / हिन्दी):** Dynamically translates every heading, label, button, risk badge, action guidance, crack time, and diagnostic finding.
- **Inclusive Design:** Semantic HTML5 landmarks (`<header>`, `<main>`, `<section>`, `<footer>`), skip-to-content link, `aria-live="polite"` result regions, color-blind safe icons + distinct border patterns, and `:focus-visible` keyboard focus rings.

---

## Security Hardening

| Layer | Protection Implemented |
| :--- | :--- |
| **SSRF Prevention** | Pure static in-memory URL parsing — zero outbound HTTP/DNS requests. |
| **Credential Privacy** | Zero password logging, storage, caching, or echoing in API responses. |
| **Input Validation** | Strict type checks, URL max `2048` chars, password max `128` chars, control-character rejection, 16 KB body limit. |
| **XSS Defense** | Server-side `html.escape` sanitization + XSS-safe DOM rendering (`textContent`, zero unsafe `innerHTML`) + strict CSP (`script-src` disallows inline scripts). |
| **HTTP Headers** | `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`. |
| **Error Hygiene** | Structured JSON errors (`400`, `404`, `405`, `413`, `500`) with zero stack-trace disclosure. |

---

## Project Structure

```text
.
├── app.py                      # Flask application factory, API routes, security middleware & error handlers
├── api/
│   └── index.py                # Vercel serverless WSGI entrypoint
├── streamlit_app.py            # Streamlit Community Cloud dashboard (shared core/ engine)
├── .streamlit/
│   └── config.toml             # Dark cybersecurity theme configuration for Streamlit
├── vercel.json                 # Vercel rewrite configuration routing traffic to Flask WSGI
├── core/
│   ├── __init__.py             # Package exports
│   ├── url_analyzer.py         # Static lexical & structural phishing heuristics (pre-compiled regexes)
│   ├── password_analyzer.py    # Shannon entropy, GPU crack-time estimator, and CSPRNG secrets generator
│   └── validators.py           # Strict payload validation & HTML output sanitization
├── templates/
│   └── index.html              # Semantic HTML5 WCAG 2.1 AA dashboard with 4 live demo presets
├── static/
│   ├── app.js                  # Decoupled frontend logic, bilingual i18n (EN/HI), Chart.js analytics
│   └── styles.css              # Accessible focus outlines, color-blind safe badges & gauge transitions
├── tests/
│   └── test_cornea_guard.py    # 34 automated pytest tests (phishing, passwords, security, headers, latency)
├── requirements.txt            # Minimal dependencies (Flask, pytest)
├── .gitignore                  # Clean Python/cache/env exclusions
└── README.md                   # Project documentation
```

---

## Deployment (Vercel & Streamlit Community Cloud)

### Deploy on Vercel (Flask Web App)
1. Go to [vercel.com/new](https://vercel.com/new) and import `sonalim549-alt/cornea-guard`.
2. Keep the default settings — `vercel.json` and `api/index.py` automatically configure the Flask WSGI runtime.
3. Click **Deploy**.

### Deploy on Streamlit Community Cloud
1. Go to [share.streamlit.io/deploy](https://share.streamlit.io/deploy) and connect `sonalim549-alt/cornea-guard`.
2. Select branch **`main`** and main file path **`streamlit_app.py`**.
3. Click **Deploy** (Streamlit Community Cloud pre-installs `streamlit` automatically while `requirements.txt` stays lean for Vercel).

---

## Installation & Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the automated test suite (34 tests):**
   ```bash
   pytest -v
   ```

3. **Launch the application:**
   ```bash
   python app.py
   ```
   Open **http://127.0.0.1:5000** in your browser.

---

## API Reference

| Method | Endpoint | Request Body / Query | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | — | Renders the Cornea-Guard interactive dashboard |
| `GET` | `/api/health` | — | Lightweight service health status |
| `POST` | `/api/scan-url` | `{"url": "https://..."}` | Static phishing inspection (`safety_score`, `risk_level`, `findings`, `scan_time_ms`) |
| `POST` | `/api/check-password` | `{"password": "..."}` | Zero-knowledge entropy & crack-time audit (never echoes password) |
| `GET` | `/api/generate-password` | `?length=20` (`12–64`) | Generates a CSPRNG password with strength metrics |

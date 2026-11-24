"use strict";

/**
 * Cornea-Guard — Decoupled Frontend Controller
 * Handles API requests, bilingual English/Hindi translation, dynamic SVG gauge,
 * Chart.js session analytics, demo presets, and XSS-safe DOM rendering.
 */

const DEMO_PRESETS = Object.freeze({
    "fake-sbi": {
        type: "url",
        value: "http://sbi-kyc-urgent-verify.xyz/login?otp=confirm",
    },
    "safe-link": {
        type: "url",
        value: "https://www.onlinesbi.sbi/personal/index.html",
    },
    "weak-password": {
        type: "password",
        value: "Password1234!",
    },
    "strong-password": {
        type: "password",
        value: "C0rnea#Sh1eld!94$Vortex_Kite",
    },
});

const I18N = Object.freeze({
    en: {
        skipToMain: "Skip to main content",
        brandTitle: "Cornea-Guard",
        zeroKnowledgePill: "✓ Zero-Storage • Zero-SSRF",
        brandSubtitle: "Real-Time Phishing & Credential Hygiene Shield",
        engineStatus: "Engine Active",
        demoHeading: "Instant Real-World Demo Presets",
        demoSubtext:
            "Test live threat detection in one click — no links are ever visited or executed.",
        presetFakeSbi: "Fake SBI KYC Link",
        presetSafeLink: "Safe Official Link",
        presetWeakPw: "Weak Password",
        presetStrongPw: "Strong Passphrase",
        dismiss: "Dismiss",
        urlSectionTitle: "Phishing Link Inspector",
        urlSectionDesc:
            "Paste any SMS, WhatsApp, banking, UPI, or delivery link. Analyzed statically without ever opening it.",
        urlInputLabel: "Suspicious or Unknown URL (max 2048 chars)",
        urlPlaceholder: "https://example.com or http://sbi-kyc-verify.xyz/login",
        scanUrlBtn: "Inspect Link",
        scanning: "Scanning...",
        metaProtocol: "Protocol:",
        metaHost: "Host:",
        metaSubdomains: "Subdomains:",
        metaHyphens: "Hyphens:",
        pwSectionTitle: "Zero-Knowledge Password Shield",
        pwSectionDesc:
            "Measure Shannon entropy, dictionary weaknesses, and GPU crack time. Passwords are never logged or stored.",
        pwInputLabel: "Password to Audit (max 128 chars — Never Stored)",
        pwPlaceholder: "Enter or generate a password...",
        showBtn: "Show",
        hideBtn: "Hide",
        checkPwBtn: "Audit Password",
        metricCrackTime: "Est. Crack Time",
        metricEntropy: "Shannon Entropy",
        metricPool: "Char Pool Size",
        metricLength: "Length",
        genTitle: "1-Click Cryptographic Password Generator",
        genDesc: "Powered by Python's CSPRNG secrets module.",
        genLengthLabel: "Length:",
        generateBtn: "Generate Strong Password",
        copyBtn: "Copy",
        copiedMsg: "✓ Strong password copied to clipboard.",
        copyFailedMsg: "⚠ Unable to access clipboard automatically.",
        verdictTitle: "Live Security Verdict",
        safetyScoreLabel: "Safety Score / 100",
        awaitingScan: "Awaiting Scan",
        defaultGuidance:
            "Paste a link, audit a password, or click a demo preset above to begin.",
        findingsHeading: "Diagnostic Findings & Explanations",
        findingsEmpty:
            "No active scan yet. Findings will appear here with plain-language risk explanations.",
        analyticsTitle: "Real-Time Session Analytics",
        avgLatency: "Avg:",
        statSafe: "Safe",
        statSuspicious: "Suspicious",
        statHighRisk: "High Risk",
        recentLogTitle: "Recent Scan Log",
        clearLogBtn: "Clear Log",
        logEmpty:
            "Session scan log is empty. Passwords are always masked and never stored.",
        footerPrivacy:
            "Cornea-Guard operates strictly in-memory: Zero SSRF outbound requests, zero password storage, WCAG 2.1 AA accessible.",
        riskLabels: {
            Safe: "Safe",
            Suspicious: "Suspicious",
            "High Risk": "High Risk",
        },
        scanTypes: {
            url: "URL Inspection",
            password: "Password Audit",
        },
        maskedPasswordLog: "•••••••• (Password Audit — Never Stored)",
        charsUnit: "chars",
        bitsUnit: "bits",
        errEmptyUrl: "Please enter a URL to inspect.",
        errEmptyPassword: "Please enter a password to audit.",
        errNetwork: "Unable to reach Cornea-Guard API. Verify the server is running.",
    },
    hi: {
        skipToMain: "मुख्य सामग्री पर जाएं",
        brandTitle: "कॉर्निया-गार्ड (Cornea-Guard)",
        zeroKnowledgePill: "✓ ज़ीरो-स्टोरेज • ज़ीरो-SSRF",
        brandSubtitle: "रियल-टाइम फ़िशिंग और पासवर्ड सुरक्षा कवच",
        engineStatus: "इंजन सक्रिय",
        demoHeading: "त्वरित लाइव डेमो प्रीसेट",
        demoSubtext:
            "एक क्लिक में रियल-टाइम सुरक्षा जांचें — किसी भी लिंक को कभी खोला या चलाया नहीं जाता।",
        presetFakeSbi: "नकली SBI KYC लिंक",
        presetSafeLink: "सुरक्षित आधिकारिक लिंक",
        presetWeakPw: "कमज़ोर पासवर्ड",
        presetStrongPw: "मजबूत पासफ़्रेज़",
        dismiss: "बंद करें",
        urlSectionTitle: "फ़िशिंग लिंक निरीक्षक",
        urlSectionDesc:
            "कोई भी SMS, WhatsApp, बैंकिंग, UPI या डिलीवरी लिंक पेस्ट करें। लिंक खोले बिना सुरक्षित जांच होती है।",
        urlInputLabel: "संदिग्ध या अज्ञात URL (अधिकतम 2048 अक्षर)",
        urlPlaceholder: "https://example.com या http://sbi-kyc-verify.xyz/login",
        scanUrlBtn: "लिंक जांचें",
        scanning: "जांच जारी...",
        metaProtocol: "प्रोटोकॉल:",
        metaHost: "होस्ट:",
        metaSubdomains: "सबडोमेन:",
        metaHyphens: "हाइफ़न:",
        pwSectionTitle: "ज़ीरो-नॉलेज पासवर्ड सुरक्षा कवच",
        pwSectionDesc:
            "शैनन एन्ट्रॉपी, सामान्य शब्द की कमज़ोरी और GPU क्रैक समय जांचें। पासवर्ड कभी सेव नहीं होता।",
        pwInputLabel: "जांच के लिए पासवर्ड (अधिकतम 128 अक्षर — कभी सेव नहीं होगा)",
        pwPlaceholder: "पासवर्ड लिखें या नया पासवर्ड बनाएं...",
        showBtn: "दिखाएं",
        hideBtn: "छुपाएं",
        checkPwBtn: "पासवर्ड जांचें",
        metricCrackTime: "अनुमानित क्रैक समय",
        metricEntropy: "शैनन एन्ट्रॉपी",
        metricPool: "अक्षर पूल आकार",
        metricLength: "लंबाई",
        genTitle: "1-क्लिक सुरक्षित पासवर्ड जनरेटर",
        genDesc: "Python के क्रिप्टोग्राफ़िक secrets मॉड्यूल द्वारा संचालित।",
        genLengthLabel: "लंबाई:",
        generateBtn: "मजबूत पासवर्ड बनाएं",
        copyBtn: "कॉपी करें",
        copiedMsg: "✓ मजबूत पासवर्ड क्लिपबोर्ड पर कॉपी हो गया।",
        copyFailedMsg: "⚠ क्लिपबोर्ड तक स्वतः पहुंच संभव नहीं हुई।",
        verdictTitle: "लाइव सुरक्षा परिणाम",
        safetyScoreLabel: "सुरक्षा स्कोर / 100",
        awaitingScan: "जांच की प्रतीक्षा",
        defaultGuidance:
            "शुरू करने के लिए कोई लिंक पेस्ट करें, पासवर्ड जांचें, या ऊपर दिए डेमो बटन पर क्लिक करें।",
        findingsHeading: "विस्तृत सुरक्षा निष्कर्ष और कारण",
        findingsEmpty:
            "अभी कोई सक्रिय जांच नहीं है। जांच के बाद सरल भाषा में सभी कारण यहां दिखेंगे।",
        analyticsTitle: "रियल-टाइम सत्र विश्लेषण",
        avgLatency: "औसत:",
        statSafe: "सुरक्षित",
        statSuspicious: "संदिग्ध",
        statHighRisk: "उच्च जोखिम",
        recentLogTitle: "हाल की जांच सूची",
        clearLogBtn: "सूची साफ़ करें",
        logEmpty:
            "जांच सूची खाली है। पासवर्ड हमेशा छिपाए जाते हैं और कभी सहेजे नहीं जाते।",
        footerPrivacy:
            "कॉर्निया-गार्ड पूरी तरह मेमोरी में चलता है: ज़ीरो SSRF नेटवर्क अनुरोध, ज़ीरो पासवर्ड संग्रहण, WCAG 2.1 AA सुलभ।",
        riskLabels: {
            Safe: "सुरक्षित (Safe)",
            Suspicious: "संदिग्ध (Suspicious)",
            "High Risk": "उच्च जोखिम (High Risk)",
        },
        scanTypes: {
            url: "URL जांच",
            password: "पासवर्ड जांच",
        },
        maskedPasswordLog: "•••••••• (पासवर्ड जांच — कभी सेव नहीं)",
        charsUnit: "अक्षर",
        bitsUnit: "बिट्स",
        errEmptyUrl: "कृपया जांचने के लिए एक URL दर्ज करें।",
        errEmptyPassword: "कृपया जांचने के लिए एक पासवर्ड दर्ज करें।",
        errNetwork: "कॉर्निया-गार्ड API से संपर्क नहीं हो सका। जांचें कि सर्वर चल रहा है।",
    },
});

const state = {
    lang: "en",
    lastScanType: null,
    lastResult: null,
    stats: {
        Safe: 0,
        Suspicious: 0,
        "High Risk": 0,
        totalLatencyMs: 0,
        totalScans: 0,
    },
    history: [],
    chart: null,
};

const GAUGE_ARC_LENGTH = 283;

/** Return active translation bundle. */
function t() {
    return I18N[state.lang] || I18N.en;
}

/** Decode HTML entities safely for display via textContent (never innerHTML). */
function unescapeForTextContent(escapedStr) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(escapedStr, "text/html");
    return doc.documentElement.textContent || "";
}

/** Show or hide the accessible error alert banner. */
function showError(message) {
    const banner = document.getElementById("error-banner");
    const text = document.getElementById("error-banner-text");
    text.textContent = message;
    banner.classList.remove("hidden");
    banner.classList.add("flex");
}

function clearError() {
    const banner = document.getElementById("error-banner");
    banner.classList.add("hidden");
    banner.classList.remove("flex");
}

/** Map risk level string to color-blind safe styles and gauge stroke color. */
function getRiskTheme(riskLevel) {
    if (riskLevel === "Safe") {
        return {
            stroke: "#10b981",
            badgeClass: "risk-badge-safe",
            bannerClass: "risk-banner-safe",
            icon: "✓",
        };
    }
    if (riskLevel === "Suspicious") {
        return {
            stroke: "#f59e0b",
            badgeClass: "risk-badge-suspicious",
            bannerClass: "risk-banner-suspicious",
            icon: "⚠",
        };
    }
    return {
        stroke: "#f43f5e",
        badgeClass: "risk-badge-high",
        bannerClass: "risk-banner-high",
        icon: "✕",
    };
}

/** Update the dynamic SVG radial gauge, badges, guidance, and findings list. */
function renderVerdict(scanType, data) {
    state.lastScanType = scanType;
    state.lastResult = data;

    const bundle = t();
    const theme = getRiskTheme(data.risk_level);
    const score = Number(data.safety_score) || 0;

    // Animate SVG semi-circle arc.
    const gaugeArc = document.getElementById("gauge-arc");
    const offset = GAUGE_ARC_LENGTH - (GAUGE_ARC_LENGTH * Math.max(0, Math.min(100, score))) / 100;
    gaugeArc.style.strokeDashoffset = String(offset);
    gaugeArc.style.stroke = theme.stroke;

    document.getElementById("gauge-score-value").textContent = String(score);

    // Update risk badge (icon + localized bold label + distinct border style).
    const riskBadge = document.getElementById("risk-badge");
    riskBadge.className = `inline-flex items-center gap-1.5 rounded-full px-4 py-1.5 text-sm font-extrabold ${theme.badgeClass}`;
    document.getElementById("risk-badge-icon").textContent = data.risk_icon || theme.icon;
    document.getElementById("risk-badge-text").textContent =
        bundle.riskLabels[data.risk_level] || data.risk_level;

    // Update scan type tag.
    const scanTag = document.getElementById("scan-type-tag");
    scanTag.textContent = bundle.scanTypes[scanType] || scanType;
    scanTag.classList.remove("hidden");

    // Update action guidance banner.
    const guidanceBanner = document.getElementById("action-guidance-banner");
    guidanceBanner.className = `mt-4 w-full rounded-xl px-4 py-3 text-center text-sm font-bold ${theme.bannerClass}`;
    const guidanceText =
        state.lang === "hi"
            ? data.action_guidance_hi || data.action_guidance
            : data.action_guidance;
    document.getElementById("action-guidance-text").textContent = `${theme.icon} ${guidanceText}`;

    // Update sub-10ms latency badges.
    const latencyText = `${Number(data.scan_time_ms).toFixed(2)} ms`;
    document.getElementById("latency-badge").textContent = latencyText;
    document.getElementById("header-latency").textContent = latencyText;

    // Render structured diagnostic findings using safe DOM nodes.
    const list = document.getElementById("findings-list");
    list.replaceChildren();

    const findings = Array.isArray(data.findings) ? data.findings : [];
    findings.forEach((item) => {
        const li = document.createElement("li");
        const sev = item.severity || "medium";
        li.className = `rounded-xl p-3.5 text-xs finding-${sev}`;

        const header = document.createElement("div");
        header.className = "flex items-center justify-between gap-2 font-bold text-slate-100";

        const titleSpan = document.createElement("span");
        const titleText = state.lang === "hi" ? item.title_hi || item.title : item.title;
        titleSpan.textContent = `${item.icon || "•"} ${titleText}`;
        header.appendChild(titleSpan);

        if (typeof item.penalty === "number" && item.penalty > 0) {
            const penaltyBadge = document.createElement("span");
            penaltyBadge.className =
                "font-mono-code rounded bg-slate-950/70 px-1.5 py-0.5 text-[11px] text-rose-300";
            penaltyBadge.textContent = `-${item.penalty}`;
            header.appendChild(penaltyBadge);
        }

        const detailP = document.createElement("p");
        detailP.className = "mt-1 leading-relaxed text-slate-200";
        const detailText = state.lang === "hi" ? item.detail_hi || item.detail : item.detail;
        detailP.textContent = unescapeForTextContent(detailText);

        li.appendChild(header);
        li.appendChild(detailP);
        list.appendChild(li);
    });
}

/** Update URL structural metadata pills safely. */
function renderUrlMetadata(data) {
    const bar = document.getElementById("url-meta-bar");
    const parsed = data.parsed || {};
    document.getElementById("meta-scheme").textContent = parsed.scheme || "none";
    document.getElementById("meta-host").textContent = unescapeForTextContent(
        parsed.hostname || "—"
    );
    document.getElementById("meta-subdomains").textContent = String(parsed.subdomain_count ?? 0);
    document.getElementById("meta-hyphens").textContent = String(parsed.hyphen_count ?? 0);
    bar.classList.remove("hidden");
    bar.classList.add("flex");
}

/** Update password entropy, crack time, and character pool badges. */
function renderPasswordMetrics(data) {
    const bundle = t();
    const grid = document.getElementById("pw-metrics-grid");
    grid.classList.remove("hidden");
    grid.classList.add("grid");

    document.getElementById("metric-crack-time").textContent =
        state.lang === "hi" ? data.crack_time_hi || data.crack_time : data.crack_time;
    document.getElementById(
        "metric-shannon-entropy"
    ).textContent = `${data.shannon_entropy_bits} ${bundle.bitsUnit}`;
    document.getElementById("metric-pool-size").textContent = String(data.character_pool_size);
    document.getElementById(
        "metric-pw-length"
    ).textContent = `${data.length} ${bundle.charsUnit}`;

    const poolBar = document.getElementById("pw-pool-badges");
    poolBar.classList.remove("hidden");
    poolBar.classList.add("flex");

    const classes = data.character_classes || {};
    const badgeConfig = [
        ["badge-lower", classes.lowercase, "a-z"],
        ["badge-upper", classes.uppercase, "A-Z"],
        ["badge-digit", classes.digits, "0-9"],
        ["badge-symbol", classes.symbols, "!@#$"],
    ];

    badgeConfig.forEach(([id, active, label]) => {
        const el = document.getElementById(id);
        el.textContent = `${active ? "✓" : "✕"} ${label}`;
        el.className = active
            ? "rounded-md border border-emerald-500/50 bg-emerald-950/60 px-2.5 py-1 font-semibold text-emerald-200"
            : "rounded-md border border-slate-700 bg-slate-900 px-2.5 py-1 font-semibold text-slate-400";
    });
}

/** Initialize the Chart.js real-time session doughnut chart. */
function initSessionChart() {
    const canvas = document.getElementById("session-chart");
    if (!canvas || typeof window.Chart === "undefined") {
        return;
    }

    const bundle = t();
    state.chart = new window.Chart(canvas, {
        type: "doughnut",
        data: {
            labels: [bundle.statSafe, bundle.statSuspicious, bundle.statHighRisk],
            datasets: [
                {
                    data: [0, 0, 0],
                    backgroundColor: ["#10b981", "#f59e0b", "#f43f5e"],
                    borderColor: "#0f172a",
                    borderWidth: 3,
                    hoverOffset: 4,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            cutout: "66%",
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: "#0f172a",
                    borderColor: "#334155",
                    borderWidth: 1,
                },
            },
        },
    });
}

/** Record scan outcome in session stats, update Chart.js, and append to scan log. */
function recordSessionScan(scanType, data, targetSummary) {
    const level = data.risk_level;
    if (Object.prototype.hasOwnProperty.call(state.stats, level)) {
        state.stats[level] += 1;
    }
    state.stats.totalScans += 1;
    state.stats.totalLatencyMs += Number(data.scan_time_ms) || 0;

    document.getElementById("count-safe").textContent = String(state.stats.Safe);
    document.getElementById("count-suspicious").textContent = String(state.stats.Suspicious);
    document.getElementById("count-high").textContent = String(state.stats["High Risk"]);

    const avg =
        state.stats.totalScans > 0
            ? state.stats.totalLatencyMs / state.stats.totalScans
            : 0;
    document.getElementById("avg-latency-value").textContent = `${avg.toFixed(2)} ms`;

    if (state.chart) {
        state.chart.data.datasets[0].data = [
            state.stats.Safe,
            state.stats.Suspicious,
            state.stats["High Risk"],
        ];
        state.chart.update();
    }

    // Store strictly sanitized/masked metadata in recent scan history (zero passwords).
    state.history.unshift({
        scanType,
        summary: targetSummary,
        score: data.safety_score,
        riskLevel: level,
        latencyMs: Number(data.scan_time_ms).toFixed(2),
        timestamp: new Date().toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
        }),
    });
    if (state.history.length > 12) {
        state.history.pop();
    }
    renderScanHistory();
}

/** Render recent scan log cleanly with XSS-safe DOM APIs. */
function renderScanHistory() {
    const list = document.getElementById("scan-log-list");
    const bundle = t();
    list.replaceChildren();

    if (state.history.length === 0) {
        const emptyLi = document.createElement("li");
        emptyLi.className = "rounded-xl border border-slate-800 bg-slate-900/50 p-3 text-xs text-slate-400";
        emptyLi.textContent = bundle.logEmpty;
        list.appendChild(emptyLi);
        return;
    }

    state.history.forEach((entry) => {
        const theme = getRiskTheme(entry.riskLevel);
        const li = document.createElement("li");
        li.className =
            "flex items-center justify-between gap-2 rounded-xl border border-slate-800 bg-slate-900/75 px-3 py-2.5 text-xs";

        const left = document.createElement("div");
        left.className = "min-w-0 flex-1";

        const topRow = document.createElement("div");
        topRow.className = "flex items-center gap-2";

        const badge = document.createElement("span");
        badge.className = `inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-bold ${theme.badgeClass}`;
        badge.textContent = `${theme.icon} ${bundle.riskLabels[entry.riskLevel] || entry.riskLevel}`;

        const timeSpan = document.createElement("span");
        timeSpan.className = "font-mono-code text-[11px] text-slate-400";
        timeSpan.textContent = `${entry.timestamp} • ${entry.latencyMs} ms`;

        topRow.appendChild(badge);
        topRow.appendChild(timeSpan);

        const targetP = document.createElement("p");
        targetP.className = "font-mono-code mt-1 truncate text-slate-200";
        targetP.textContent =
            entry.scanType === "password" ? bundle.maskedPasswordLog : entry.summary;

        left.appendChild(topRow);
        left.appendChild(targetP);

        const scoreEl = document.createElement("span");
        scoreEl.className = "font-mono-code text-sm font-extrabold text-white";
        scoreEl.textContent = `${entry.score}`;

        li.appendChild(left);
        li.appendChild(scoreEl);
        list.appendChild(li);
    });
}

/** Call POST /api/scan-url and update dashboard UI. */
async function scanUrl(urlValue) {
    clearError();
    const trimmed = (urlValue || "").trim();
    if (!trimmed) {
        showError(t().errEmptyUrl);
        return;
    }

    const btn = document.getElementById("url-scan-btn");
    btn.disabled = true;

    try {
        const response = await fetch("/api/scan-url", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: trimmed }),
        });
        const data = await response.json();
        if (!response.ok) {
            showError(data.error || "URL scan failed.");
            return;
        }
        renderVerdict("url", data);
        renderUrlMetadata(data);
        const displaySummary = unescapeForTextContent(data.url_sanitized || trimmed);
        recordSessionScan("url", data, displaySummary);
    } catch (_err) {
        showError(t().errNetwork);
    } finally {
        btn.disabled = false;
    }
}

/** Call POST /api/check-password and update dashboard UI without storing password. */
async function checkPassword(passwordValue) {
    clearError();
    if (!passwordValue || passwordValue.length === 0) {
        showError(t().errEmptyPassword);
        return;
    }

    const btn = document.getElementById("pw-scan-btn");
    btn.disabled = true;

    try {
        const response = await fetch("/api/check-password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password: passwordValue }),
        });
        const data = await response.json();
        if (!response.ok) {
            showError(data.error || "Password audit failed.");
            return;
        }
        renderVerdict("password", data);
        renderPasswordMetrics(data);
        recordSessionScan("password", data, null);
    } catch (_err) {
        showError(t().errNetwork);
    } finally {
        btn.disabled = false;
    }
}

/** Call GET /api/generate-password, fill input, reveal Copy button, and audit it. */
async function generateStrongPassword() {
    clearError();
    const lengthSelect = document.getElementById("gen-length-select");
    const length = Number(lengthSelect.value) || 20;
    const copyStatus = document.getElementById("copy-status");
    copyStatus.textContent = "";

    try {
        const response = await fetch(`/api/generate-password?length=${encodeURIComponent(length)}`);
        const data = await response.json();
        if (!response.ok) {
            showError(data.error || "Unable to generate password.");
            return;
        }

        const pwInput = document.getElementById("password-input");
        pwInput.value = data.password;
        pwInput.type = "text";

        const toggleBtn = document.getElementById("toggle-pw-visibility");
        toggleBtn.setAttribute("aria-pressed", "true");
        toggleBtn.textContent = t().hideBtn;

        const copyBtn = document.getElementById("copy-pw-btn");
        copyBtn.classList.remove("hidden");
        copyBtn.classList.add("inline-flex");

        await checkPassword(data.password);
    } catch (_err) {
        showError(t().errNetwork);
    }
}

/** Dynamically apply selected language (English or Hindi) across the entire UI. */
function setLanguage(lang) {
    state.lang = lang === "hi" ? "hi" : "en";
    document.documentElement.lang = state.lang;

    const bundle = t();
    document.querySelectorAll("[data-i18n]").forEach((el) => {
        const key = el.getAttribute("data-i18n");
        if (key && Object.prototype.hasOwnProperty.call(bundle, key)) {
            el.textContent = bundle[key];
        }
    });

    document.getElementById("url-input").placeholder = bundle.urlPlaceholder;
    document.getElementById("password-input").placeholder = bundle.pwPlaceholder;

    // Update toggle button states.
    const enBtn = document.getElementById("lang-en-btn");
    const hiBtn = document.getElementById("lang-hi-btn");
    const isHi = state.lang === "hi";
    enBtn.setAttribute("aria-pressed", String(!isHi));
    hiBtn.setAttribute("aria-pressed", String(isHi));
    enBtn.className = isHi
        ? "rounded-md px-3 py-1.5 text-xs font-bold text-slate-300 transition hover:text-white"
        : "rounded-md bg-sky-600 px-3 py-1.5 text-xs font-bold text-white transition";
    hiBtn.className = isHi
        ? "rounded-md bg-sky-600 px-3 py-1.5 text-xs font-bold text-white transition"
        : "rounded-md px-3 py-1.5 text-xs font-bold text-slate-300 transition hover:text-white";

    // Sync password show/hide label.
    const pwInput = document.getElementById("password-input");
    const toggleBtn = document.getElementById("toggle-pw-visibility");
    toggleBtn.textContent = pwInput.type === "text" ? bundle.hideBtn : bundle.showBtn;

    // Update Chart.js labels if active.
    if (state.chart) {
        state.chart.data.labels = [bundle.statSafe, bundle.statSuspicious, bundle.statHighRisk];
        state.chart.update();
    }

    // Re-render current active verdict, password metrics, and scan history in chosen language.
    if (state.lastResult && state.lastScanType) {
        renderVerdict(state.lastScanType, state.lastResult);
        if (state.lastScanType === "password") {
            renderPasswordMetrics(state.lastResult);
        }
    }
    renderScanHistory();
}

/** Wire all event listeners on DOMContentLoaded. */
document.addEventListener("DOMContentLoaded", () => {
    initSessionChart();

    // Language toggle buttons.
    document.getElementById("lang-en-btn").addEventListener("click", () => setLanguage("en"));
    document.getElementById("lang-hi-btn").addEventListener("click", () => setLanguage("hi"));

    // Dismiss error banner.
    document.getElementById("error-dismiss-btn").addEventListener("click", clearError);

    // URL scan form.
    document.getElementById("url-scan-form").addEventListener("submit", (event) => {
        event.preventDefault();
        const urlInput = document.getElementById("url-input");
        scanUrl(urlInput.value);
    });

    // Password check form.
    document.getElementById("password-scan-form").addEventListener("submit", (event) => {
        event.preventDefault();
        const pwInput = document.getElementById("password-input");
        checkPassword(pwInput.value);
    });

    // Show/hide password toggle.
    document.getElementById("toggle-pw-visibility").addEventListener("click", () => {
        const pwInput = document.getElementById("password-input");
        const toggleBtn = document.getElementById("toggle-pw-visibility");
        const showing = pwInput.type === "text";
        pwInput.type = showing ? "password" : "text";
        toggleBtn.setAttribute("aria-pressed", String(!showing));
        toggleBtn.textContent = showing ? t().showBtn : t().hideBtn;
    });

    // 1-Click cryptographic password generator.
    document.getElementById("generate-pw-btn").addEventListener("click", generateStrongPassword);

    // Copy generated password to clipboard.
    document.getElementById("copy-pw-btn").addEventListener("click", async () => {
        const pwInput = document.getElementById("password-input");
        const copyStatus = document.getElementById("copy-status");
        try {
            await navigator.clipboard.writeText(pwInput.value);
            copyStatus.textContent = t().copiedMsg;
        } catch (_err) {
            copyStatus.textContent = t().copyFailedMsg;
        }
    });

    // 4 One-Click Demo Presets.
    document.querySelectorAll("[data-preset]").forEach((btn) => {
        btn.addEventListener("click", () => {
            const presetKey = btn.getAttribute("data-preset");
            const preset = DEMO_PRESETS[presetKey];
            if (!preset) {
                return;
            }
            if (preset.type === "url") {
                const urlInput = document.getElementById("url-input");
                urlInput.value = preset.value;
                scanUrl(preset.value);
            } else if (preset.type === "password") {
                const pwInput = document.getElementById("password-input");
                pwInput.value = preset.value;
                checkPassword(preset.value);
            }
        });
    });

    // Clear recent scan history log.
    document.getElementById("clear-log-btn").addEventListener("click", () => {
        state.history = [];
        renderScanHistory();
    });
});

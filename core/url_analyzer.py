"""Pure static lexical and structural URL phishing analyzer for Cornea-Guard.

All analysis is performed strictly in memory using pre-compiled regular
expressions and standard-library URL parsing. No outbound network requests are
ever executed, eliminating SSRF risk.
"""

from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import SplitResult, urlsplit

from core.validators import sanitize_output

# Pre-compiled regular expressions for sub-millisecond O(n) evaluation.
_SCHEME_RE: re.Pattern[str] = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*):")
_DANGEROUS_SCHEME_RE: re.Pattern[str] = re.compile(
    r"^(javascript|data|vbscript|file|blob):",
    re.IGNORECASE,
)
_IPV4_RE: re.Pattern[str] = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)
_IPV6_RE: re.Pattern[str] = re.compile(r"^[0-9a-fA-F:]+$")
_NUMERIC_IP_RE: re.Pattern[str] = re.compile(r"^(?:0x[0-9a-fA-F]+|\d{7,15})$")
_TOKEN_SPLIT_RE: re.Pattern[str] = re.compile(r"[^a-z0-9]+")
_ENCODED_HEX_RE: re.Pattern[str] = re.compile(r"%[0-9a-fA-F]{2}")
_HTML_INJECTION_RE: re.Pattern[str] = re.compile(r"[<>\"']")
_DOMAIN_LABEL_RE: re.Pattern[str] = re.compile(r"^[a-z0-9-]+$")
_URGENCY_KEYWORDS_RE: re.Pattern[str] = re.compile(
    r"(?<![a-z0-9])("
    r"verify|verification|urgent|urgently|kyc|suspend|suspended|suspension|"
    r"winner|winning|free|alert|blocked|block|expire|expired|expiry|"
    r"claim|reward|prize|refund|otp|reactivate|unlock|confirm|immediately|"
    r"bonus|cashback|lottery|update-kyc|pan-update|aadhaar-update|"
    r"account-locked|security-alert|limited-time"
    r")(?![a-z0-9])",
    re.IGNORECASE,
)

SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {
        "xyz",
        "top",
        "tk",
        "click",
        "ml",
        "ga",
        "cf",
        "gq",
        "buzz",
        "work",
        "zip",
        "mov",
        "loan",
        "win",
        "bid",
        "icu",
        "vip",
        "club",
        "online",
        "site",
        "pw",
        "cc",
        "cam",
        "rest",
        "surf",
    }
)

URL_SHORTENERS: frozenset[str] = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "cutt.ly",
        "rb.gy",
        "shorturl.at",
        "tiny.cc",
    }
)

BRAND_OFFICIAL_DOMAINS: dict[str, tuple[str, ...]] = {
    "sbi": ("sbi.co.in", "onlinesbi.sbi", "sbicard.com", "yonobusiness.sbi"),
    "hdfc": ("hdfcbank.com", "hdfc.com", "hdfcsec.com"),
    "icici": ("icicibank.com", "icicidirect.com"),
    "axis": ("axisbank.com",),
    "kotak": ("kotak.com", "kotakbank.com"),
    "pnb": ("pnbindia.in", "netpnb.com"),
    "paypal": ("paypal.com", "paypal.me"),
    "amazon": ("amazon.com", "amazon.in", "amazon.co.uk", "aws.amazon.com"),
    "paytm": ("paytm.com", "paytmbank.com"),
    "phonepe": ("phonepe.com",),
    "google": ("google.com", "google.co.in", "googleapis.com"),
    "gpay": ("pay.google.com",),
    "upi": ("npci.org.in", "bhimupi.org.in"),
    "npci": ("npci.org.in",),
    "uidai": ("uidai.gov.in",),
    "aadhaar": ("uidai.gov.in",),
    "incometax": ("incometax.gov.in", "incometaxindia.gov.in"),
    "epfo": ("epfindia.gov.in",),
    "indiapost": ("indiapost.gov.in",),
    "dhl": ("dhl.com", "dhl.co.in"),
    "fedex": ("fedex.com",),
    "bluedart": ("bluedart.com",),
    "flipkart": ("flipkart.com",),
    "microsoft": ("microsoft.com", "live.com", "office.com", "outlook.com"),
    "apple": ("apple.com", "icloud.com"),
    "netflix": ("netflix.com",),
    "whatsapp": ("whatsapp.com", "wa.me"),
    "instagram": ("instagram.com",),
    "facebook": ("facebook.com", "fb.com"),
    "chase": ("chase.com",),
    "wellsfargo": ("wellsfargo.com",),
    "citibank": ("citi.com", "citibank.com", "citibank.co.in"),
}

_LEET_TABLE_L: dict[int, str] = str.maketrans(
    {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"}
)
_LEET_TABLE_I: dict[int, str] = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"}
)

_SECOND_LEVEL_PUBLIC_SUFFIXES: frozenset[str] = frozenset(
    {"co.in", "gov.in", "org.in", "net.in", "ac.in", "co.uk", "gov.uk", "com.au"}
)


def _is_official_domain(hostname: str, official_domains: tuple[str, ...]) -> bool:
    """Return True if ``hostname`` is an exact match or subdomain of an official domain."""
    for official in official_domains:
        if hostname == official or hostname.endswith(f".{official}"):
            return True
    return False


def _is_edit_distance_one(source: str, target: str) -> bool:
    """Return True if ``source`` and ``target`` differ by at most 1 edit or swap."""
    if source == target:
        return True
    len_s: int = len(source)
    len_t: int = len(target)
    if abs(len_s - len_t) > 1:
        return False

    if len_s == len_t:
        diffs: list[int] = [i for i in range(len_s) if source[i] != target[i]]
        if len(diffs) == 1:
            return True
        if len(diffs) == 2:
            first, second = diffs
            return (
                second == first + 1
                and source[first] == target[second]
                and source[second] == target[first]
            )
        return False

    shorter, longer = (source, target) if len_s < len_t else (target, source)
    idx_s: int = 0
    idx_l: int = 0
    found_diff: bool = False
    while idx_s < len(shorter) and idx_l < len(longer):
        if shorter[idx_s] != longer[idx_l]:
            if found_diff:
                return False
            found_diff = True
            idx_l += 1
        else:
            idx_s += 1
            idx_l += 1
    return True


def _normalize_homoglyphs(token: str) -> tuple[str, str]:
    """Generate leetspeak/homoglyph normalized variants of a domain token."""
    base: str = token.replace("rn", "m").replace("vv", "w")
    return base.translate(_LEET_TABLE_L), base.translate(_LEET_TABLE_I)


def _detect_brand_spoofing(hostname: str) -> tuple[str | None, str | None]:
    """Detect typosquatting or unauthorized brand names inside a hostname.

    Returns:
        Tuple of ``(brand_name, match_type)`` where ``match_type`` is either
        ``"typosquatting"`` or ``"impersonation"``, or ``(None, None)`` if clean.
    """
    tokens: list[str] = [t for t in _TOKEN_SPLIT_RE.split(hostname) if t]
    if not tokens:
        return None, None

    for brand, official_domains in BRAND_OFFICIAL_DOMAINS.items():
        if _is_official_domain(hostname, official_domains):
            continue

        for token in tokens:
            if token == brand:
                return brand, "impersonation"

            norm_l, norm_i = _normalize_homoglyphs(token)
            if (norm_l == brand or norm_i == brand) and token != brand:
                return brand, "typosquatting"

            if len(brand) >= 5:
                if brand in token:
                    return brand, "impersonation"
                if brand in norm_l or brand in norm_i:
                    return brand, "typosquatting"
                if len(token) >= 5 and _is_edit_distance_one(norm_l, brand):
                    return brand, "typosquatting"

    return None, None


def _extract_tld_and_subdomains(hostname: str) -> tuple[str, int, str]:
    """Extract TLD, subdomain count, and registrable domain from a hostname."""
    labels: list[str] = [part for part in hostname.split(".") if part]
    if len(labels) < 2:
        return "", 0, hostname

    tld: str = labels[-1]
    last_two: str = f"{labels[-2]}.{labels[-1]}"
    if last_two in _SECOND_LEVEL_PUBLIC_SUFFIXES and len(labels) >= 3:
        registrable: str = f"{labels[-3]}.{last_two}"
        subdomain_count: int = max(0, len(labels) - 3)
    else:
        registrable = last_two
        subdomain_count = max(0, len(labels) - 2)

    return tld, subdomain_count, registrable


def _is_raw_ip(hostname: str) -> bool:
    """Return True if ``hostname`` is an IPv4, IPv6, or numeric/hex IP literal."""
    if not hostname:
        return False
    if _IPV4_RE.match(hostname):
        return True
    if ":" in hostname and _IPV6_RE.match(hostname):
        return True
    if _NUMERIC_IP_RE.match(hostname):
        return True
    return False


def _make_finding(
    finding_id: str,
    severity: str,
    penalty: int,
    title: str,
    detail: str,
    title_hi: str,
    detail_hi: str,
) -> dict[str, Any]:
    """Build a structured, bilingual finding dictionary."""
    icon_map: dict[str, str] = {"high": "✕", "medium": "⚠", "low": "⚠", "safe": "✓"}
    return {
        "id": finding_id,
        "severity": severity,
        "icon": icon_map.get(severity, "⚠"),
        "penalty": penalty,
        "title": title,
        "detail": detail,
        "title_hi": title_hi,
        "detail_hi": detail_hi,
    }


def analyze_url(url: str) -> dict[str, Any]:
    """Perform static phishing risk inspection on a validated URL string.

    Args:
        url: Pre-validated URL string (<= 2048 chars).

    Returns:
        Structured dictionary containing ``safety_score``, ``risk_level``,
        ``reasons``, ``findings``, parsed structural metadata, sanitized URL,
        bilingual action guidance, and ``scan_time_ms``.
    """
    start_ns: int = time.perf_counter_ns()
    findings: list[dict[str, Any]] = []
    score: int = 100

    sanitized_url: str = sanitize_output(url)
    lower_url: str = url.lower()

    # Check for dangerous non-web executable schemes (e.g., javascript:, data:).
    if _DANGEROUS_SCHEME_RE.match(lower_url):
        scheme_name: str = sanitize_output(lower_url.split(":", 1)[0])
        findings.append(
            _make_finding(
                finding_id="DANGEROUS_SCHEME",
                severity="high",
                penalty=75,
                title="Executable or Unsafe URL Scheme",
                detail=(
                    f"Uses '{scheme_name}:' scheme, which can execute scripts or "
                    "inject malicious payloads directly in the browser."
                ),
                title_hi="खतरनाक या असुरक्षित URL स्कीम",
                detail_hi=(
                    f"यह लिंक '{scheme_name}:' स्कीम का उपयोग करता है, जो आपके ब्राउज़र में "
                    "हानिकारक कोड चला सकता है।"
                ),
            )
        )
        score -= 75
        return _finalize_url_report(
            score=score,
            findings=findings,
            sanitized_url=sanitized_url,
            scheme=scheme_name,
            hostname="",
            tld="",
            subdomain_count=0,
            hyphen_count=0,
            has_https=False,
            path_length=len(url),
            start_ns=start_ns,
        )

    # Check for raw HTML/XSS injection attempts embedded inside the input.
    if _HTML_INJECTION_RE.search(url):
        findings.append(
            _make_finding(
                finding_id="SUSPICIOUS_HTML_CHARS",
                severity="high",
                penalty=45,
                title="Suspicious Script or Markup Characters",
                detail=(
                    "URL contains raw HTML/script characters (<, >, quotes) commonly "
                    "associated with cross-site scripting (XSS) injection links."
                ),
                title_hi="संदिग्ध स्क्रिप्ट या HTML अक्षर",
                detail_hi=(
                    "इस URL में कच्चे HTML/स्क्रिप्ट अक्षर (<, >, उद्धरण चिह्न) हैं, "
                    "जो अक्सर XSS हमले वाले लिंक में पाए जाते हैं।"
                ),
            )
        )
        score -= 45

    has_explicit_scheme: bool = bool(_SCHEME_RE.match(url))
    parse_target: str = url if has_explicit_scheme else f"http://{url}"
    parsed: SplitResult = urlsplit(parse_target)

    scheme: str = parsed.scheme.lower()
    has_https: bool = has_explicit_scheme and scheme == "https"
    raw_hostname: str = (parsed.hostname or "").lower().rstrip(".")
    safe_hostname: str = sanitize_output(raw_hostname) if raw_hostname else "unknown"

    # 1. Missing HTTPS check.
    if not has_https:
        findings.append(
            _make_finding(
                finding_id="MISSING_HTTPS",
                severity="medium",
                penalty=20,
                title="Missing HTTPS Encryption",
                detail=(
                    "Link does not enforce HTTPS. Sensitive inputs like passwords "
                    "or UPI/banking details can be intercepted in transit."
                ),
                title_hi="HTTPS एन्क्रिप्शन अनुपस्थित है",
                detail_hi=(
                    "यह लिंक सुरक्षित HTTPS का उपयोग नहीं करता। पासवर्ड या बैंकिंग "
                    "जानकारी बीच में चुराई जा सकती है।"
                ),
            )
        )
        score -= 20

    # 2. '@' symbol userinfo redirection trick.
    if "@" in parsed.netloc:
        findings.append(
            _make_finding(
                finding_id="AT_SYMBOL_REDIRECT",
                severity="high",
                penalty=40,
                title="'@' Symbol Redirection Trick",
                detail=(
                    f"Contains '@' in the address authority. Browsers ignore text "
                    f"before '@' and actually navigate to '{safe_hostname}'."
                ),
                title_hi="'@' चिह्न द्वारा भ्रामक रीडायरेक्ट",
                detail_hi=(
                    f"पते में '@' चिह्न है। ब्राउज़र '@' से पहले का भाग अनदेखा कर देता है "
                    f"और आपको वास्तव में '{safe_hostname}' पर ले जाता है।"
                ),
            )
        )
        score -= 40

    # 3. Raw IP address hostname check.
    is_ip_host: bool = _is_raw_ip(raw_hostname)
    if is_ip_host:
        findings.append(
            _make_finding(
                finding_id="RAW_IP_ADDRESS",
                severity="high",
                penalty=45,
                title="Raw IP Address Used Instead of Domain",
                detail=(
                    f"Hostname '{safe_hostname}' is a raw IP address. Legitimate "
                    "banks and major services use verified domain names."
                ),
                title_hi="डोमेन के बजाय सीधे IP पते का उपयोग",
                detail_hi=(
                    f"होस्टनेम '{safe_hostname}' एक सीधा IP पता है। असली बैंक और "
                    "आधिकारिक सेवाएं हमेशा सत्यापित डोमेन नाम उपयोग करती हैं।"
                ),
            )
        )
        score -= 45

    tld, subdomain_count, registrable = _extract_tld_and_subdomains(raw_hostname)
    hyphen_count: int = raw_hostname.count("-")

    # 4. Punycode / IDN homograph check.
    if "xn--" in raw_hostname:
        findings.append(
            _make_finding(
                finding_id="PUNYCODE_HOMOGRAPH",
                severity="high",
                penalty=35,
                title="Punycode / Homograph Domain Detected",
                detail=(
                    "Domain uses Punycode ('xn--'), which attackers abuse to mimic "
                    "trusted brands with lookalike international characters."
                ),
                title_hi="पनीकोड (Punycode) / हमशक्ल डोमेन का पता चला",
                detail_hi=(
                    "यह डोमेन 'xn--' का उपयोग करता है, जिसका दुरुपयोग ठग विश्वसनीय "
                    "ब्रांड जैसे दिखने वाले नकली अक्षर बनाने के लिए करते हैं।"
                ),
            )
        )
        score -= 35

    # 5. Typosquatting & brand spoofing check.
    if raw_hostname and not is_ip_host:
        spoofed_brand, spoof_type = _detect_brand_spoofing(raw_hostname)
        if spoofed_brand is not None:
            brand_label: str = spoofed_brand.upper() if len(spoofed_brand) <= 4 else spoofed_brand.title()
            if spoof_type == "typosquatting":
                findings.append(
                    _make_finding(
                        finding_id="BRAND_TYPOSQUATTING",
                        severity="high",
                        penalty=45,
                        title=f"Brand Typosquatting ({brand_label})",
                        detail=(
                            f"Domain '{safe_hostname}' mimics '{brand_label}' using "
                            "character substitutions or intentional spelling tricks."
                        ),
                        title_hi=f"ब्रांड की नकल / टाइपोस्क्वाटिंग ({brand_label})",
                        detail_hi=(
                            f"डोमेन '{safe_hostname}' अक्षरों में हेरफेर करके '{brand_label}' "
                            "की नकल करने की कोशिश कर रहा है।"
                        ),
                    )
                )
                score -= 45
            else:
                findings.append(
                    _make_finding(
                        finding_id="BRAND_IMPERSONATION",
                        severity="high",
                        penalty=40,
                        title=f"Unofficial Brand Impersonation ({brand_label})",
                        detail=(
                            f"Domain '{safe_hostname}' uses the '{brand_label}' brand "
                            "name on an unofficial domain not owned by that organization."
                        ),
                        title_hi=f"अनधिकृत ब्रांड नाम का दुरुपयोग ({brand_label})",
                        detail_hi=(
                            f"डोमेन '{safe_hostname}' आधिकारिक वेबसाइट न होते हुए भी "
                            f"'{brand_label}' ब्रांड के नाम का उपयोग कर रहा है।"
                        ),
                    )
                )
                score -= 40

    # 6. Suspicious Top-Level Domain (TLD) check.
    if tld in SUSPICIOUS_TLDS:
        safe_tld: str = sanitize_output(tld)
        findings.append(
            _make_finding(
                finding_id="SUSPICIOUS_TLD",
                severity="medium",
                penalty=25,
                title=f"High-Risk Top-Level Domain (.{safe_tld})",
                detail=(
                    f"The '.{safe_tld}' domain extension is heavily abused in disposable "
                    "phishing campaigns and scam links."
                ),
                title_hi=f"उच्च-जोखिम वाला डोमेन एक्सटेंशन (.{safe_tld})",
                detail_hi=(
                    f"'.{safe_tld}' एक्सटेंशन का उपयोग फिशिंग और ऑनलाइन धोखाधड़ी "
                    "के अस्थायी लिंक में बहुत अधिक किया जाता है।"
                ),
            )
        )
        score -= 25

    # 7. URL shortener obfuscation check.
    if raw_hostname in URL_SHORTENERS or registrable in URL_SHORTENERS:
        findings.append(
            _make_finding(
                finding_id="URL_SHORTENER",
                severity="medium",
                penalty=20,
                title="Shortened URL Hides True Destination",
                detail=(
                    f"Shortener '{safe_hostname}' conceals the final website address, "
                    "making it easy to disguise malicious redirects."
                ),
                title_hi="शॉर्ट किया गया URL असली पता छुपाता है",
                detail_hi=(
                    f"लिंक शॉर्टनर '{safe_hostname}' अंतिम वेबसाइट का पता छुपाता है, "
                    "जिसका उपयोग खतरनाक लिंक छिपाने के लिए किया जा सकता है।"
                ),
            )
        )
        score -= 20

    # 8. Excessive subdomains check.
    if not is_ip_host and subdomain_count >= 3:
        findings.append(
            _make_finding(
                finding_id="EXCESSIVE_SUBDOMAINS",
                severity="medium",
                penalty=20,
                title=f"Excessive Subdomains ({subdomain_count} Levels)",
                detail=(
                    f"Contains {subdomain_count} nested subdomain levels to push the "
                    "real root domain out of sight on mobile screens."
                ),
                title_hi=f"अत्यधिक सबडोमेन ({subdomain_count} स्तर)",
                detail_hi=(
                    f"इस लिंक में {subdomain_count} सबडोमेन स्तर हैं ताकि मोबाइल स्क्रीन "
                    "पर असली डोमेन नाम छिप जाए।"
                ),
            )
        )
        score -= 20

    # 9. Excessive hyphens in hostname check.
    if not is_ip_host and hyphen_count >= 2:
        penalty: int = 20 if hyphen_count >= 3 else 12
        findings.append(
            _make_finding(
                finding_id="EXCESSIVE_HYPHENS",
                severity="medium",
                penalty=penalty,
                title=f"Excessive Hyphens in Domain ({hyphen_count} Hyphens)",
                detail=(
                    f"Hostname contains {hyphen_count} hyphens, a common structure in "
                    "lookalike scam domains (e.g., brand-kyc-verify)."
                ),
                title_hi=f"डोमेन में अत्यधिक हाइफ़न ({hyphen_count} हाइफ़न)",
                detail_hi=(
                    f"डोमेन नाम में {hyphen_count} हाइफ़न ('-') हैं, जो अक्सर नकली "
                    "बैंकिंग या KYC धोखाधड़ी वाले लिंक में होते हैं।"
                ),
            )
        )
        score -= penalty

    # 10. Urgency / social engineering keywords across hostname, path, and query.
    inspect_surface: str = f"{raw_hostname}{parsed.path}?{parsed.query}"
    matched_keywords: list[str] = sorted(
        {m.group(1).lower() for m in _URGENCY_KEYWORDS_RE.finditer(inspect_surface)}
    )
    if matched_keywords:
        keyword_penalty: int = min(30, 12 + (len(matched_keywords) - 1) * 7)
        safe_kw_list: str = ", ".join(sanitize_output(k) for k in matched_keywords[:5])
        findings.append(
            _make_finding(
                finding_id="URGENCY_KEYWORDS",
                severity="high" if len(matched_keywords) >= 2 else "medium",
                penalty=keyword_penalty,
                title="Phishing / Urgency Lure Keywords",
                detail=(
                    f"Detected high-pressure scam keywords ({safe_kw_list}) commonly "
                    "used to trick users into urgent KYC or login actions."
                ),
                title_hi="फिशिंग और जल्दबाज़ी वाले भ्रामक शब्द",
                detail_hi=(
                    f"लिंक में संदिग्ध शब्द ({safe_kw_list}) पाए गए हैं, जिनका उपयोग "
                    "यूज़र को डराकर तुरंत KYC या लॉगिन करवाने के लिए किया जाता है।"
                ),
            )
        )
        score -= keyword_penalty

    # 11. Non-standard port or excessive URL length / percent-encoding obfuscation.
    try:
        port: int | None = parsed.port
    except ValueError:
        port = None
        findings.append(
            _make_finding(
                finding_id="MALFORMED_PORT",
                severity="medium",
                penalty=20,
                title="Malformed Port Number",
                detail="URL contains an invalid or obfuscated port specification.",
                title_hi="अमान्य पोर्ट नंबर",
                detail_hi="इस URL में अमान्य या संदिग्ध पोर्ट नंबर दिया गया है।",
            )
        )
        score -= 20

    if port is not None and port not in (80, 443):
        findings.append(
            _make_finding(
                finding_id="NON_STANDARD_PORT",
                severity="low",
                penalty=12,
                title=f"Non-Standard Network Port (:{port})",
                detail=(
                    f"Connects to unusual port {port} instead of standard web ports "
                    "(80/443), often seen on temporary attacker servers."
                ),
                title_hi=f"गैर-मानक नेटवर्क पोर्ट (:{port})",
                detail_hi=(
                    f"यह लिंक सामान्य वेब पोर्ट (80/443) के बजाय असामान्य पोर्ट {port} "
                    "का उपयोग करता है।"
                ),
            )
        )
        score -= 12

    encoded_matches: int = len(_ENCODED_HEX_RE.findall(url))
    if encoded_matches >= 4:
        findings.append(
            _make_finding(
                finding_id="EXCESSIVE_ENCODING",
                severity="low",
                penalty=12,
                title="Heavy Percent-Encoding Obfuscation",
                detail=(
                    f"Contains {encoded_matches} hex-encoded sequences used to hide "
                    "suspicious parameters or destination paths."
                ),
                title_hi="संदिग्ध हेक्स-एन्कोडिंग छिपाव",
                detail_hi=(
                    f"लिंक में {encoded_matches} एन्कोडेड अक्षर हैं जिनका उपयोग असली "
                    "पते या पैरामीटर को छुपाने के लिए किया जा सकता है।"
                ),
            )
        )
        score -= 12

    if len(url) > 120:
        findings.append(
            _make_finding(
                finding_id="EXCESSIVE_URL_LENGTH",
                severity="low",
                penalty=10,
                title=f"Unusually Long URL ({len(url)} Characters)",
                detail=(
                    "Overly long URLs are often used to hide malicious redirects "
                    "or tracking tokens past the visible address bar."
                ),
                title_hi=f"असामान्य रूप से लंबा URL ({len(url)} अक्षर)",
                detail_hi=(
                    "बहुत लंबे URL का उपयोग अक्सर एड्रेस बार में संदिग्ध भाग को "
                    "छुपाने के लिए किया जाता है।"
                ),
            )
        )
        score -= 10

    # Malformed / missing hostname fallback.
    if not raw_hostname or (
        not is_ip_host
        and ("." not in raw_hostname or not all(_DOMAIN_LABEL_RE.match(lbl) for lbl in raw_hostname.split(".") if lbl))
    ):
        findings.append(
            _make_finding(
                finding_id="INVALID_HOSTNAME",
                severity="medium",
                penalty=30,
                title="Malformed or Incomplete Domain Structure",
                detail=(
                    "The URL does not contain a valid, standard internet domain name."
                ),
                title_hi="अमान्य या अधूरा डोमेन ढांचा",
                detail_hi="इस URL में कोई वैध और मानक इंटरनेट डोमेन नाम नहीं है।",
            )
        )
        score -= 30

    return _finalize_url_report(
        score=score,
        findings=findings,
        sanitized_url=sanitized_url,
        scheme=scheme if has_explicit_scheme else "none",
        hostname=safe_hostname,
        tld=sanitize_output(tld),
        subdomain_count=subdomain_count,
        hyphen_count=hyphen_count,
        has_https=has_https,
        path_length=len(parsed.path),
        start_ns=start_ns,
    )


def _finalize_url_report(
    *,
    score: int,
    findings: list[dict[str, Any]],
    sanitized_url: str,
    scheme: str,
    hostname: str,
    tld: str,
    subdomain_count: int,
    hyphen_count: int,
    has_https: bool,
    path_length: int,
    start_ns: int,
) -> dict[str, Any]:
    """Clamp score, determine risk classification, and attach execution latency."""
    clamped_score: int = max(0, min(100, score))

    if clamped_score >= 75:
        risk_level: str = "Safe"
        risk_icon: str = "✓"
        action_guidance: str = "Safe to Open — No phishing indicators detected."
        action_guidance_hi: str = "खोलने के लिए सुरक्षित — कोई फिशिंग संकेत नहीं मिला।"
    elif clamped_score >= 40:
        risk_level = "Suspicious"
        risk_icon = "⚠"
        action_guidance = "Proceed with Caution — Verify the sender and domain before clicking."
        action_guidance_hi = "सावधानी बरतें — क्लिक करने से पहले भेजने वाले और डोमेन की जांच करें।"
    else:
        risk_level = "High Risk"
        risk_icon = "✕"
        action_guidance = "Do Not Click — Phishing Risk. Never enter OTP, PIN, or passwords here."
        action_guidance_hi = "क्लिक न करें — फिशिंग का उच्च खतरा। यहां कभी OTP, PIN या पासवर्ड न डालें।"

    if not findings:
        findings.append(
            _make_finding(
                finding_id="ALL_CHECKS_PASSED",
                severity="safe",
                penalty=0,
                title="Verified Structural Hygiene",
                detail=(
                    "Uses HTTPS encryption with a clean domain structure and no "
                    "detected spoofing, IP literals, or urgency lure keywords."
                ),
                title_hi="सुरक्षित संरचना सत्यापित",
                detail_hi=(
                    "यह लिंक HTTPS एन्क्रिप्शन और साफ डोमेन संरचना का उपयोग करता है; "
                    "कोई धोखाधड़ी या संदिग्ध संकेत नहीं मिला।"
                ),
            )
        )

    reasons: list[str] = [f"{item['title']}: {item['detail']}" for item in findings]
    elapsed_ms: float = round((time.perf_counter_ns() - start_ns) / 1_000_000, 3)

    return {
        "safety_score": clamped_score,
        "risk_level": risk_level,
        "risk_icon": risk_icon,
        "action_guidance": action_guidance,
        "action_guidance_hi": action_guidance_hi,
        "reasons": reasons,
        "findings": findings,
        "url_sanitized": sanitized_url,
        "parsed": {
            "scheme": sanitize_output(scheme),
            "hostname": hostname,
            "tld": tld,
            "has_https": has_https,
            "subdomain_count": subdomain_count,
            "hyphen_count": hyphen_count,
            "path_length": path_length,
        },
        "scan_time_ms": elapsed_ms,
    }

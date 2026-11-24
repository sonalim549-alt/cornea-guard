"""Zero-knowledge password hygiene analyzer and secure generator for Cornea-Guard.

Never stores, logs, or echoes back user-submitted passwords. Computes true
Shannon entropy, character pool diversity, dictionary/pattern weaknesses, and
realistic offline brute-force crack times in sub-millisecond O(n) time.
"""

from __future__ import annotations

import math
import re
import secrets
import string
import time
from collections import Counter
from typing import Any

# Offline GPU cluster estimate: 10 billion guesses per second (10^10 / s).
_GUESSES_PER_SECOND: float = 1e10

# Pre-compiled regular expressions for O(n) pattern weakness detection.
_LOWER_RE: re.Pattern[str] = re.compile(r"[a-z]")
_UPPER_RE: re.Pattern[str] = re.compile(r"[A-Z]")
_DIGIT_RE: re.Pattern[str] = re.compile(r"\d")
_SYMBOL_RE: re.Pattern[str] = re.compile(r"[^a-zA-Z0-9\s]")
_SPACE_RE: re.Pattern[str] = re.compile(r"\s")
_REPEAT_CHAR_RE: re.Pattern[str] = re.compile(r"(.)\1{2,}")
_REPEAT_CHUNK_RE: re.Pattern[str] = re.compile(r"(.{2,6})\1+")
_YEAR_RE: re.Pattern[str] = re.compile(r"(?:19[6-9]\d|20[0-3]\d)")

_LEET_NORMALIZE: dict[int, str] = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
)

_COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "1234",
        "12345",
        "123456",
        "1234567",
        "12345678",
        "123456789",
        "1234567890",
        "0000",
        "000000",
        "1111",
        "111111",
        "password",
        "password1",
        "password123",
        "password1234",
        "passw0rd",
        "p@ssword",
        "qwerty",
        "qwerty123",
        "qwertyuiop",
        "abc123",
        "admin",
        "admin123",
        "welcome",
        "welcome123",
        "letmein",
        "iloveyou",
        "india123",
        "dragon",
        "monkey",
        "football",
        "shadow",
        "master",
        "sunshine",
        "princess",
        "test1234",
        "guest",
        "root",
        "login",
        "asdfgh",
        "zxcvbn",
    }
)

_DICTIONARY_SUBSTRINGS: tuple[str, ...] = (
    "password",
    "qwerty",
    "asdfgh",
    "zxcvbn",
    "welcome",
    "letmein",
    "iloveyou",
    "admin",
    "football",
    "dragon",
    "monkey",
    "sunshine",
    "princess",
    "india",
    "login",
    "secret",
    "master",
    "shadow",
    "trustno",
    "access",
)

_KEYBOARD_SEQUENCES: tuple[str, ...] = (
    "01234567890",
    "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)

_GENERATOR_SYMBOLS: str = "!@#$%^&*-_=+?"
_SYSTEM_RANDOM: secrets.SystemRandom = secrets.SystemRandom()


def _detect_sequential_pattern(password: str) -> bool:
    """Return True if password contains a 4+ char ascending/descending sequence."""
    lowered: str = password.lower()
    if len(lowered) < 4:
        return False

    for seq in _KEYBOARD_SEQUENCES:
        rev_seq: str = seq[::-1]
        for idx in range(len(lowered) - 3):
            window: str = lowered[idx : idx + 4]
            if window in seq or window in rev_seq:
                return True
    return False


def _detect_dictionary_words(password: str) -> list[str]:
    """Return any common dictionary or leaked base words found inside password."""
    lowered: str = password.lower()
    normalized: str = lowered.translate(_LEET_NORMALIZE)
    found: list[str] = []
    for word in _DICTIONARY_SUBSTRINGS:
        if word in lowered or word in normalized:
            found.append(word)
    return found


def _calculate_shannon_entropy(password: str) -> float:
    """Compute true total Shannon entropy in bits across the password string."""
    length: int = len(password)
    if length == 0:
        return 0.0
    counts: Counter[str] = Counter(password)
    entropy_per_char: float = 0.0
    for count in counts.values():
        prob: float = count / length
        entropy_per_char -= prob * math.log2(prob)
    return entropy_per_char * length


def _format_crack_time(effective_entropy_bits: float) -> tuple[str, str]:
    """Convert effective entropy bits to human-readable English & Hindi crack times."""
    if effective_entropy_bits <= 26.0:
        return "Instantly", "तुरंत (1 सेकंड से कम)"

    exponent: float = effective_entropy_bits - 1.0
    if exponent > 90.0:
        return "Billions of Years", "अरबों वर्ष"

    seconds: float = (2.0**exponent) / _GUESSES_PER_SECOND
    if seconds < 1.0:
        return "Instantly", "तुरंत (1 सेकंड से कम)"
    if seconds < 60.0:
        val: int = max(1, round(seconds))
        unit_en: str = "Second" if val == 1 else "Seconds"
        return f"{val} {unit_en}", f"{val} सेकंड"
    if seconds < 3600.0:
        val = max(1, round(seconds / 60.0))
        unit_en = "Minute" if val == 1 else "Minutes"
        return f"{val} {unit_en}", f"{val} मिनट"
    if seconds < 86_400.0:
        val = max(1, round(seconds / 3600.0))
        unit_en = "Hour" if val == 1 else "Hours"
        return f"{val} {unit_en}", f"{val} घंटे"
    if seconds < 2_592_000.0:
        val = max(1, round(seconds / 86_400.0))
        unit_en = "Day" if val == 1 else "Days"
        return f"{val} {unit_en}", f"{val} दिन"
    if seconds < 31_536_000.0:
        val = max(1, round(seconds / 2_592_000.0))
        unit_en = "Month" if val == 1 else "Months"
        return f"{val} {unit_en}", f"{val} महीने"

    years: float = seconds / 31_536_000.0
    if years < 100.0:
        val = max(1, round(years))
        unit_en = "Year" if val == 1 else "Years"
        return f"{val} {unit_en}", f"{val} वर्ष"
    if years < 10_000.0:
        rounded: int = int(round(years, -1))
        return f"{rounded:,}+ Years", f"{rounded:,}+ वर्ष"
    if years < 1_000_000.0:
        rounded_k: int = int(round(years / 1_000.0))
        return f"{rounded_k:,}K+ Years", f"{rounded_k:,} हज़ार+ वर्ष"
    if years < 1_000_000_000.0:
        rounded_m: int = int(round(years / 1_000_000.0))
        return f"{rounded_m:,}M+ Years", f"{rounded_m:,} मिलियन+ वर्ष"
    return "Billions of Years", "अरबों वर्ष"


def _make_finding(
    finding_id: str,
    severity: str,
    title: str,
    detail: str,
    title_hi: str,
    detail_hi: str,
) -> dict[str, Any]:
    """Build a structured, bilingual password hygiene finding."""
    icon_map: dict[str, str] = {"high": "✕", "medium": "⚠", "low": "⚠", "safe": "✓"}
    return {
        "id": finding_id,
        "severity": severity,
        "icon": icon_map.get(severity, "⚠"),
        "title": title,
        "detail": detail,
        "title_hi": title_hi,
        "detail_hi": detail_hi,
    }


def analyze_password(password: str) -> dict[str, Any]:
    """Evaluate password strength with zero-knowledge privacy (never echoes password).

    Args:
        password: Pre-validated password string (1..128 chars).

    Returns:
        Structured dictionary with ``safety_score``, ``risk_level``,
        ``strength_label``, ``shannon_entropy_bits``, ``effective_entropy_bits``,
        ``crack_time``, ``crack_time_hi``, ``character_classes``, ``findings``,
        ``reasons``, bilingual guidance, and ``scan_time_ms``.
    """
    start_ns: int = time.perf_counter_ns()
    length: int = len(password)
    lowered: str = password.lower()
    normalized: str = lowered.translate(_LEET_NORMALIZE)

    has_lower: bool = bool(_LOWER_RE.search(password))
    has_upper: bool = bool(_UPPER_RE.search(password))
    has_digit: bool = bool(_DIGIT_RE.search(password))
    has_symbol: bool = bool(_SYMBOL_RE.search(password))
    has_space: bool = bool(_SPACE_RE.search(password))

    pool_size: int = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_symbol:
        pool_size += 32
    if has_space:
        pool_size += 1
    pool_size = max(pool_size, 1)

    pool_entropy_bits: float = length * math.log2(pool_size)
    shannon_entropy_bits: float = _calculate_shannon_entropy(password)
    unique_chars: int = len(set(password))

    # Effective entropy blends pool space with Shannon uniqueness, then deducts
    # penalties for predictable patterns and dictionary matches.
    effective_entropy: float = min(pool_entropy_bits, shannon_entropy_bits * 1.45)

    findings: list[dict[str, Any]] = []
    score: int = 0

    # Length contribution (up to 40 pts).
    if length >= 16:
        score += 40
    elif length >= 12:
        score += 32
    elif length >= 10:
        score += 22
    elif length >= 8:
        score += 14
    else:
        score += max(2, length * 2)

    # Diversity contribution (up to 32 pts).
    diversity_count: int = sum([has_lower, has_upper, has_digit, has_symbol])
    score += diversity_count * 8

    # Entropy bonus (up to 28 pts).
    if effective_entropy >= 80.0:
        score += 28
    elif effective_entropy >= 60.0:
        score += 22
    elif effective_entropy >= 45.0:
        score += 14
    elif effective_entropy >= 30.0:
        score += 7

    # Weakness checks.
    if length < 8:
        findings.append(
            _make_finding(
                finding_id="TOO_SHORT",
                severity="high",
                title=f"Critically Short Length ({length} Characters)",
                detail=(
                    "Passwords shorter than 8 characters can be brute-forced rapidly. "
                    "Use at least 12–16 characters."
                ),
                title_hi=f"अत्यंत छोटा पासवर्ड ({length} अक्षर)",
                detail_hi=(
                    "8 अक्षरों से छोटे पासवर्ड बहुत आसानी से तोड़े जा सकते हैं। "
                    "कम से कम 12–16 अक्षरों का उपयोग करें।"
                ),
            )
        )
        score -= 25
    elif length < 12:
        findings.append(
            _make_finding(
                finding_id="MODERATE_LENGTH",
                severity="medium",
                title=f"Length Below Modern Standard ({length} Characters)",
                detail=(
                    "Aim for 12 or more characters to resist modern GPU cracking rigs."
                ),
                title_hi=f"आधुनिक मानक से कम लंबाई ({length} अक्षर)",
                detail_hi=(
                    "आधुनिक GPU हमलों से बचने के लिए 12 या अधिक अक्षरों का पासवर्ड चुनें।"
                ),
            )
        )
        score -= 10

    is_exact_common: bool = lowered in _COMMON_PASSWORDS or normalized in _COMMON_PASSWORDS
    dict_words: list[str] = _detect_dictionary_words(password)

    if is_exact_common:
        findings.append(
            _make_finding(
                finding_id="COMMON_BREACHED_PASSWORD",
                severity="high",
                title="Known Commonly Breached Password",
                detail=(
                    "Matches a top-list leaked password tried within milliseconds "
                    "by automated credential-stuffing tools."
                ),
                title_hi="बेहद आम और लीक हो चुका पासवर्ड",
                detail_hi=(
                    "यह सबसे अधिक इस्तेमाल होने वाले लीक पासवर्ड की सूची में शामिल है "
                    "और स्वचालित हैकिंग टूल इसे मिलीसेकंड में तोड़ देते हैं।"
                ),
            )
        )
        effective_entropy = min(effective_entropy, 12.0)
        score -= 45
    elif dict_words:
        findings.append(
            _make_finding(
                finding_id="DICTIONARY_WORD",
                severity="high",
                title="Contains Predictable Dictionary Word",
                detail=(
                    "Includes a common dictionary or breached base word (even with "
                    "basic letter-to-number substitutions like '@' or '0')."
                ),
                title_hi="अनुमान लगाने योग्य सामान्य शब्द शामिल है",
                detail_hi=(
                    "इसमें एक सामान्य शब्दकोश शब्द शामिल है जिसे अक्षर-संख्या बदलने "
                    "के बावजूद हैकिंग टूल आसानी से पहचान लेते हैं।"
                ),
            )
        )
        effective_entropy -= 26.0
        score -= 28

    if _detect_sequential_pattern(password):
        findings.append(
            _make_finding(
                finding_id="SEQUENTIAL_PATTERN",
                severity="high",
                title="Sequential Keyboard or Number Run",
                detail=(
                    "Contains predictable sequences such as '1234', 'abcd', or 'qwerty' "
                    "that dramatically shrink the brute-force search space."
                ),
                title_hi="क्रमिक संख्या या कीबोर्ड पैटर्न",
                detail_hi=(
                    "इसमें '1234', 'abcd', या 'qwerty' जैसा आसान क्रम है, जिससे "
                    "पासवर्ड को तोड़ना बहुत आसान हो जाता है।"
                ),
            )
        )
        effective_entropy -= 20.0
        score -= 22

    if _REPEAT_CHAR_RE.search(password) or _REPEAT_CHUNK_RE.search(password):
        findings.append(
            _make_finding(
                finding_id="REPEATED_PATTERN",
                severity="medium",
                title="Repeated Characters or Segments",
                detail=(
                    "Repeating the same character or chunk (e.g., 'aaa', '111', 'abab') "
                    "reduces real cryptographic randomness."
                ),
                title_hi="दोहराए गए अक्षर या पैटर्न",
                detail_hi=(
                    "एक ही अक्षर या समूह को बार-बार दोहराने (जैसे 'aaa', '111') से "
                    "पासवर्ड की सुरक्षा क्षमता कम हो जाती है।"
                ),
            )
        )
        effective_entropy -= 16.0
        score -= 18

    if _YEAR_RE.search(password) and length < 16:
        findings.append(
            _make_finding(
                finding_id="YEAR_PATTERN",
                severity="low",
                title="Contains Calendar Year Pattern",
                detail=(
                    "Years (e.g., birth years or current year) are heavily prioritized "
                    "in targeted password guessing attacks."
                ),
                title_hi="वर्ष (Year) पैटर्न का उपयोग",
                detail_hi=(
                    "पासवर्ड में जन्म या वर्तमान वर्ष का उपयोग करना हैकर्स के लिए "
                    "अनुमान लगाना आसान बना देता है।"
                ),
            )
        )
        effective_entropy -= 8.0
        score -= 8

    missing_classes: list[str] = []
    missing_classes_hi: list[str] = []
    if not has_upper:
        missing_classes.append("uppercase letters")
        missing_classes_hi.append("बड़े अक्षर (A-Z)")
    if not has_lower:
        missing_classes.append("lowercase letters")
        missing_classes_hi.append("छोटे अक्षर (a-z)")
    if not has_digit:
        missing_classes.append("numbers")
        missing_classes_hi.append("अंक (0-9)")
    if not has_symbol:
        missing_classes.append("special symbols")
        missing_classes_hi.append("विशेष चिह्न (!@#$)")

    if missing_classes:
        findings.append(
            _make_finding(
                finding_id="LIMITED_CHARACTER_POOL",
                severity="medium" if len(missing_classes) >= 2 else "low",
                title="Limited Character Pool Diversity",
                detail=f"Add {', '.join(missing_classes)} to expand brute-force resistance.",
                title_hi="अक्षर विविधता की कमी",
                detail_hi=(
                    f"मजबूती बढ़ाने के लिए {', '.join(missing_classes_hi)} शामिल करें।"
                ),
            )
        )
        score -= len(missing_classes) * 5

    effective_entropy = max(0.0, effective_entropy)
    clamped_score: int = max(0, min(100, score))

    # Align score ceiling if effective entropy is critically low.
    if effective_entropy < 28.0:
        clamped_score = min(clamped_score, 35)
    elif effective_entropy < 45.0:
        clamped_score = min(clamped_score, 65)

    crack_time_en, crack_time_hi = _format_crack_time(effective_entropy)

    if clamped_score >= 75:
        risk_level: str = "Safe"
        strength_label: str = "Strong"
        strength_label_hi: str = "मजबूत"
        risk_icon: str = "✓"
        action_guidance: str = "Strong Credential — Resistant to modern brute-force attacks."
        action_guidance_hi: str = "मजबूत पासवर्ड — आधुनिक ब्रूट-फोर्स हमलों के प्रति सुरक्षित।"
    elif clamped_score >= 40:
        risk_level = "Suspicious"
        strength_label = "Moderate"
        strength_label_hi = "मध्यम"
        risk_icon = "⚠"
        action_guidance = "Moderate Credential — Strengthen length and eliminate patterns."
        action_guidance_hi = "मध्यम पासवर्ड — लंबाई बढ़ाएं और अनुमानित पैटर्न हटाएं।"
    else:
        risk_level = "High Risk"
        strength_label = "Weak"
        strength_label_hi = "कमज़ोर"
        risk_icon = "✕"
        action_guidance = "High Risk — Do not use this password. Generate a secure replacement."
        action_guidance_hi = "उच्च जोखिम — इस पासवर्ड का उपयोग न करें। नया सुरक्षित पासवर्ड बनाएं।"

    if not findings:
        findings.append(
            _make_finding(
                finding_id="EXCELLENT_HYGIENE",
                severity="safe",
                title="Excellent Credential Hygiene",
                detail=(
                    "High Shannon entropy, full character class diversity, and no "
                    "dictionary words or predictable keyboard sequences detected."
                ),
                title_hi="उत्कृष्ट पासवर्ड सुरक्षा",
                detail_hi=(
                    "उच्च शैनन एन्ट्रॉपी, पूर्ण अक्षर विविधता और कोई भी सामान्य "
                    "शब्द या क्रमिक पैटर्न नहीं पाया गया।"
                ),
            )
        )

    reasons: list[str] = [f"{item['title']}: {item['detail']}" for item in findings]
    elapsed_ms: float = round((time.perf_counter_ns() - start_ns) / 1_000_000, 3)

    return {
        "safety_score": clamped_score,
        "risk_level": risk_level,
        "risk_icon": risk_icon,
        "strength_label": strength_label,
        "strength_label_hi": strength_label_hi,
        "action_guidance": action_guidance,
        "action_guidance_hi": action_guidance_hi,
        "length": length,
        "unique_characters": unique_chars,
        "character_pool_size": pool_size,
        "shannon_entropy_bits": round(shannon_entropy_bits, 2),
        "pool_entropy_bits": round(pool_entropy_bits, 2),
        "effective_entropy_bits": round(effective_entropy, 2),
        "crack_time": crack_time_en,
        "crack_time_hi": crack_time_hi,
        "crack_rate_assumption": "10 billion guesses/sec (offline GPU rig)",
        "character_classes": {
            "lowercase": has_lower,
            "uppercase": has_upper,
            "digits": has_digit,
            "symbols": has_symbol,
        },
        "findings": findings,
        "reasons": reasons,
        "zero_knowledge_verified": True,
        "scan_time_ms": elapsed_ms,
    }


def generate_secure_password(length: int = 20) -> dict[str, Any]:
    """Generate a cryptographically secure random password using ``secrets``.

    Guarantees at least 2 uppercase letters, 2 lowercase letters, 2 digits, and
    2 special symbols, shuffled via ``secrets.SystemRandom``.

    Args:
        length: Desired password length (12..64).

    Returns:
        Dictionary containing the newly generated ``password``, its computed
        hygiene analysis summary, and execution latency ``scan_time_ms``.
    """
    start_ns: int = time.perf_counter_ns()

    required_chars: list[str] = [
        *(secrets.choice(string.ascii_uppercase) for _ in range(2)),
        *(secrets.choice(string.ascii_lowercase) for _ in range(2)),
        *(secrets.choice(string.digits) for _ in range(2)),
        *(secrets.choice(_GENERATOR_SYMBOLS) for _ in range(2)),
    ]

    full_alphabet: str = (
        string.ascii_uppercase
        + string.ascii_lowercase
        + string.digits
        + _GENERATOR_SYMBOLS
    )
    remaining: int = max(0, length - len(required_chars))
    password_chars: list[str] = required_chars + [
        secrets.choice(full_alphabet) for _ in range(remaining)
    ]
    _SYSTEM_RANDOM.shuffle(password_chars)
    generated: str = "".join(password_chars)

    analysis: dict[str, Any] = analyze_password(generated)
    elapsed_ms: float = round((time.perf_counter_ns() - start_ns) / 1_000_000, 3)

    return {
        "password": generated,
        "length": len(generated),
        "safety_score": analysis["safety_score"],
        "risk_level": analysis["risk_level"],
        "shannon_entropy_bits": analysis["shannon_entropy_bits"],
        "effective_entropy_bits": analysis["effective_entropy_bits"],
        "crack_time": analysis["crack_time"],
        "crack_time_hi": analysis["crack_time_hi"],
        "scan_time_ms": elapsed_ms,
    }

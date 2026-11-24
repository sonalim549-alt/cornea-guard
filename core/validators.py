"""Strict input validation and output sanitization helpers for Cornea-Guard."""

from __future__ import annotations

import html
import re
from typing import Any

MAX_URL_LENGTH: int = 2048
MAX_PASSWORD_LENGTH: int = 128
MIN_GENERATED_PASSWORD_LENGTH: int = 12
MAX_GENERATED_PASSWORD_LENGTH: int = 64
DEFAULT_GENERATED_PASSWORD_LENGTH: int = 20

_CONTROL_CHAR_RE: re.Pattern[str] = re.compile(r"[\x00-\x1f\x7f]")


class ValidationError(ValueError):
    """Raised when user-supplied API input fails strict validation."""

    def __init__(self, message: str, code: str = "VALIDATION_ERROR") -> None:
        super().__init__(message)
        self.message: str = message
        self.code: str = code


def sanitize_output(value: str) -> str:
    """Escape HTML special characters to neutralize XSS in reflected output.

    Args:
        value: Untrusted text intended for safe display.

    Returns:
        HTML-escaped string with quotes converted to entities.
    """
    return html.escape(value, quote=True)


def validate_url_input(raw_url: Any) -> str:
    """Validate and normalize a user-submitted URL string without fetching it.

    Args:
        raw_url: Raw value extracted from the JSON request payload.

    Returns:
        Trimmed URL string guaranteed to satisfy length and character bounds.

    Raises:
        ValidationError: If the value is missing, non-string, empty, contains
            ASCII control characters, or exceeds ``MAX_URL_LENGTH``.
    """
    if raw_url is None or not isinstance(raw_url, str):
        raise ValidationError(
            "Field 'url' is required and must be a non-empty string.",
            code="INVALID_URL_TYPE",
        )

    cleaned: str = raw_url.strip()
    if not cleaned:
        raise ValidationError(
            "Field 'url' cannot be empty or whitespace.",
            code="EMPTY_URL",
        )

    if len(cleaned) > MAX_URL_LENGTH:
        raise ValidationError(
            f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters.",
            code="URL_TOO_LONG",
        )

    if _CONTROL_CHAR_RE.search(cleaned):
        raise ValidationError(
            "URL contains disallowed control characters.",
            code="INVALID_URL_CHARACTERS",
        )

    return cleaned


def validate_password_input(raw_password: Any) -> str:
    """Validate a user-submitted password string without logging or mutating it.

    Spaces are intentionally preserved so multi-word passphrases are scored
    accurately.

    Args:
        raw_password: Raw value extracted from the JSON request payload.

    Returns:
        Validated password string within the allowed length limit.

    Raises:
        ValidationError: If the value is missing, non-string, empty, or exceeds
            ``MAX_PASSWORD_LENGTH``.
    """
    if raw_password is None or not isinstance(raw_password, str):
        raise ValidationError(
            "Field 'password' is required and must be a string.",
            code="INVALID_PASSWORD_TYPE",
        )

    if len(raw_password) == 0:
        raise ValidationError(
            "Field 'password' cannot be empty.",
            code="EMPTY_PASSWORD",
        )

    if len(raw_password) > MAX_PASSWORD_LENGTH:
        raise ValidationError(
            f"Password exceeds maximum allowed length of {MAX_PASSWORD_LENGTH} characters.",
            code="PASSWORD_TOO_LONG",
        )

    return raw_password


def validate_length_param(
    raw_length: Any,
    default: int = DEFAULT_GENERATED_PASSWORD_LENGTH,
) -> int:
    """Validate the optional password generator length query parameter.

    Args:
        raw_length: Raw query parameter value or None.
        default: Default password length when omitted.

    Returns:
        Validated integer length within ``[12, 64]``.

    Raises:
        ValidationError: If the provided length is not an integer or falls
            outside the safe allowed bounds.
    """
    if raw_length is None or raw_length == "":
        return default

    if isinstance(raw_length, bool):
        raise ValidationError(
            "Parameter 'length' must be an integer.",
            code="INVALID_LENGTH",
        )

    try:
        length: int = int(raw_length)
    except (TypeError, ValueError) as exc:
        raise ValidationError(
            "Parameter 'length' must be a valid integer.",
            code="INVALID_LENGTH",
        ) from exc

    if not (MIN_GENERATED_PASSWORD_LENGTH <= length <= MAX_GENERATED_PASSWORD_LENGTH):
        raise ValidationError(
            (
                f"Parameter 'length' must be between "
                f"{MIN_GENERATED_PASSWORD_LENGTH} and {MAX_GENERATED_PASSWORD_LENGTH}."
            ),
            code="LENGTH_OUT_OF_RANGE",
        )

    return length

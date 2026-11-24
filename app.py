"""Cornea-Guard — Real-Time Phishing & Credential Hygiene Shield.

Flask application factory, REST API endpoints, HTTP security middleware, and
structured error handling with zero-storage password privacy.
"""

from __future__ import annotations

from typing import Any

from flask import Flask, Response, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from core.password_analyzer import analyze_password, generate_secure_password
from core.url_analyzer import analyze_url
from core.validators import (
    ValidationError,
    validate_length_param,
    validate_password_input,
    validate_url_input,
)

_CSP_POLICY: str = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)


def _error_response(message: str, code: str, status_code: int) -> tuple[Response, int]:
    """Build a clean, structured JSON error response without leaking internals."""
    return jsonify({"error": message, "code": code, "status": status_code}), status_code


def _extract_json_object() -> dict[str, Any]:
    """Parse the incoming request body strictly as a JSON object."""
    if not request.is_json:
        raise ValidationError(
            "Request Content-Type must be 'application/json'.",
            code="UNSUPPORTED_MEDIA_TYPE",
        )

    payload: Any = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise ValidationError(
            "Request body must be a valid JSON object.",
            code="MALFORMED_JSON",
        )
    return payload


def create_app() -> Flask:
    """Create and configure the Cornea-Guard Flask application instance."""
    app: Flask = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
    app.json.sort_keys = False

    @app.after_request
    def apply_security_headers(response: Response) -> Response:
        """Attach defense-in-depth HTTP security headers to every response."""
        response.headers["Content-Security-Policy"] = _CSP_POLICY
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=()"
        )
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = (
                "no-store, no-cache, must-revalidate, max-age=0"
            )
            response.headers["Pragma"] = "no-cache"
        return response

    @app.route("/", methods=["GET"])
    def index() -> str:
        """Render the accessible Cornea-Guard cybersecurity dashboard."""
        return render_template("index.html")

    @app.route("/api/health", methods=["GET"])
    def health_check() -> tuple[Response, int]:
        """Return lightweight service health status."""
        return jsonify({"status": "ok", "service": "Cornea-Guard"}), 200

    @app.route("/api/scan-url", methods=["POST"])
    def scan_url_endpoint() -> tuple[Response, int]:
        """Inspect a user-submitted URL statically without making network calls."""
        payload: dict[str, Any] = _extract_json_object()
        validated_url: str = validate_url_input(payload.get("url"))
        result: dict[str, Any] = analyze_url(validated_url)
        return jsonify(result), 200

    @app.route("/api/check-password", methods=["POST"])
    def check_password_endpoint() -> tuple[Response, int]:
        """Analyze password entropy and crack time with zero-storage privacy."""
        payload: dict[str, Any] = _extract_json_object()
        validated_password: str = validate_password_input(payload.get("password"))
        result: dict[str, Any] = analyze_password(validated_password)
        return jsonify(result), 200

    @app.route("/api/generate-password", methods=["GET"])
    def generate_password_endpoint() -> tuple[Response, int]:
        """Generate a cryptographically secure random password using secrets."""
        length: int = validate_length_param(request.args.get("length"))
        result: dict[str, Any] = generate_secure_password(length=length)
        return jsonify(result), 200

    @app.errorhandler(ValidationError)
    def handle_validation_error(exc: ValidationError) -> tuple[Response, int]:
        """Return HTTP 400 with structured details for input validation failures."""
        return _error_response(exc.message, exc.code, 400)

    @app.errorhandler(400)
    def handle_bad_request(_exc: HTTPException) -> tuple[Response, int]:
        """Return structured JSON 400 error."""
        return _error_response(
            "Bad request. Please verify your JSON payload.",
            "BAD_REQUEST",
            400,
        )

    @app.errorhandler(404)
    def handle_not_found(_exc: HTTPException) -> tuple[Response, int]:
        """Return structured JSON 404 error."""
        return _error_response("Requested resource was not found.", "NOT_FOUND", 404)

    @app.errorhandler(405)
    def handle_method_not_allowed(_exc: HTTPException) -> tuple[Response, int]:
        """Return structured JSON 405 error for unsupported HTTP methods."""
        return _error_response(
            "HTTP method is not allowed for this endpoint.",
            "METHOD_NOT_ALLOWED",
            405,
        )

    @app.errorhandler(413)
    def handle_payload_too_large(_exc: HTTPException) -> tuple[Response, int]:
        """Return structured JSON 413 error for oversized request payloads."""
        return _error_response(
            "Request payload exceeds the maximum allowed size.",
            "PAYLOAD_TOO_LARGE",
            413,
        )

    @app.errorhandler(500)
    def handle_internal_error(_exc: Exception) -> tuple[Response, int]:
        """Return safe JSON 500 error without exposing stack traces."""
        return _error_response(
            "An internal server error occurred. Please try again.",
            "INTERNAL_SERVER_ERROR",
            500,
        )

    return app


app: Flask = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

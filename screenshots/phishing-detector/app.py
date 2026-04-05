"""
app.py
------
PhishGuard AI – Flask Backend
Provides REST API endpoints for URL, email, and HTML phishing analysis.
Includes rate limiting, request logging, and scan history.
"""

import os
import json
import time
import logging
import sqlite3
from datetime import datetime
from functools import wraps
from collections import defaultdict

from flask import Flask, request, jsonify, render_template, send_from_directory

# ──────────────────────────────────────────────
#  App Bootstrap
# ──────────────────────────────────────────────

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "phishguard-dev-secret")

# ──────────────────────────────────────────────
#  Logging Setup
# ──────────────────────────────────────────────

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("logs/phishguard.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("phishguard")

# ──────────────────────────────────────────────
#  Database (SQLite – scan history)
# ──────────────────────────────────────────────

DB_PATH = "logs/scan_history.db"

def init_db():
    """Create the scan history table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type   TEXT    NOT NULL,
            target      TEXT,
            risk_score  REAL,
            verdict     TEXT,
            issues      TEXT,
            scanned_at  TEXT    NOT NULL,
            ip_address  TEXT,
            duration_ms REAL
        )
    """)
    conn.commit()
    conn.close()


def log_scan_to_db(scan_type: str, target: str, result: dict,
                   ip: str, duration_ms: float):
    """Persist a scan result to SQLite."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            """INSERT INTO scans
               (scan_type, target, risk_score, verdict, issues, scanned_at, ip_address, duration_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_type,
                target[:500] if target else None,
                result.get("risk_score"),
                result.get("verdict"),
                json.dumps(result.get("issues", [])),
                result.get("scanned_at", datetime.utcnow().isoformat()),
                ip,
                duration_ms,
            ),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("DB log error: %s", e)


# ──────────────────────────────────────────────
#  Rate Limiting  (in-memory, per IP)
# ──────────────────────────────────────────────

RATE_LIMIT_REQUESTS = 30   # max requests
RATE_LIMIT_WINDOW   = 60   # per 60 seconds

_rate_store: dict = defaultdict(list)   # ip → [timestamps]


def rate_limit(f):
    """Decorator: reject requests that exceed the per-IP rate limit."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        ip  = request.remote_addr or "unknown"
        now = time.time()

        # Purge timestamps outside the window
        _rate_store[ip] = [t for t in _rate_store[ip] if now - t < RATE_LIMIT_WINDOW]

        if len(_rate_store[ip]) >= RATE_LIMIT_REQUESTS:
            logger.warning("Rate limit exceeded for %s", ip)
            return jsonify({
                "error": "Rate limit exceeded. Try again later.",
                "limit": RATE_LIMIT_REQUESTS,
                "window_seconds": RATE_LIMIT_WINDOW,
            }), 429

        _rate_store[ip].append(now)
        return f(*args, **kwargs)
    return wrapper


# ──────────────────────────────────────────────
#  Lazy-load ML model (loaded once on first use)
# ──────────────────────────────────────────────

_model_cache = None

def get_cached_model():
    global _model_cache
    if _model_cache is None:
        from model import get_model
        _model_cache = get_model()
        logger.info("ML model loaded into cache.")
    return _model_cache


# ══════════════════════════════════════════════
#  ROUTES – Frontend
# ══════════════════════════════════════════════

@app.route("/")
def index():
    """Serve the main UI."""
    return render_template("index.html")


@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory("static", filename)


# ══════════════════════════════════════════════
#  ROUTES – REST API
# ══════════════════════════════════════════════

@app.route("/api/scan-url", methods=["POST"])
@rate_limit
def api_scan_url():
    """
    POST /api/scan-url
    Body: { "url": "https://example.com" }
    Returns phishing analysis with risk score and issues.
    """
    data = request.get_json(silent=True) or {}
    url  = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "Missing 'url' field"}), 400

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    logger.info("URL scan requested: %s", url)
    start = time.time()

    try:
        from utils.scanner import scan_url
        result = scan_url(url, get_cached_model())
    except Exception as e:
        logger.exception("URL scan failed: %s", e)
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500

    duration_ms = round((time.time() - start) * 1000, 2)
    result["duration_ms"] = duration_ms
    log_scan_to_db("url", url, result, request.remote_addr, duration_ms)

    return jsonify(result)


@app.route("/api/scan-email", methods=["POST"])
@rate_limit
def api_scan_email():
    """
    POST /api/scan-email
    Body: { "email": "<raw email text with headers and body>" }
    Returns phishing analysis of email content.
    """
    data       = request.get_json(silent=True) or {}
    email_text = (data.get("email") or "").strip()

    if not email_text:
        return jsonify({"error": "Missing 'email' field"}), 400

    if len(email_text) > 200_000:
        return jsonify({"error": "Email too large (max 200KB)"}), 413

    logger.info("Email scan requested (%d chars)", len(email_text))
    start = time.time()

    try:
        from utils.scanner import scan_email
        result = scan_email(email_text, get_cached_model())
    except Exception as e:
        logger.exception("Email scan failed: %s", e)
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500

    duration_ms = round((time.time() - start) * 1000, 2)
    result["duration_ms"] = duration_ms
    log_scan_to_db("email", email_text[:200], result, request.remote_addr, duration_ms)

    return jsonify(result)


@app.route("/api/scan-html", methods=["POST"])
@rate_limit
def api_scan_html():
    """
    POST /api/scan-html
    Body: { "html": "<raw HTML source code>" }
    Returns phishing analysis of HTML content.
    """
    data = request.get_json(silent=True) or {}
    html = (data.get("html") or "").strip()

    if not html:
        return jsonify({"error": "Missing 'html' field"}), 400

    if len(html) > 500_000:
        return jsonify({"error": "HTML too large (max 500KB)"}), 413

    logger.info("HTML scan requested (%d chars)", len(html))
    start = time.time()

    try:
        from utils.scanner import scan_html
        result = scan_html(html, get_cached_model())
    except Exception as e:
        logger.exception("HTML scan failed: %s", e)
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500

    duration_ms = round((time.time() - start) * 1000, 2)
    result["duration_ms"] = duration_ms
    log_scan_to_db("html", None, result, request.remote_addr, duration_ms)

    return jsonify(result)


@app.route("/api/history", methods=["GET"])
def api_history():
    """
    GET /api/history?limit=20
    Returns the most recent scan records from the database.
    """
    limit = min(int(request.args.get("limit", 20)), 100)
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/model-info", methods=["GET"])
def api_model_info():
    """GET /api/model-info — returns metadata about the loaded ML model."""
    from model import get_model_info
    return jsonify(get_model_info())


@app.route("/api/health", methods=["GET"])
def api_health():
    """GET /api/health — simple health-check endpoint."""
    return jsonify({
        "status":  "ok",
        "service": "PhishGuard AI",
        "version": "1.0.0",
        "time":    datetime.utcnow().isoformat(),
    })


@app.route("/api/report", methods=["POST"])
@rate_limit
def api_generate_report():
    """
    POST /api/report
    Body: { "result": <scan_result_dict>, "format": "json" | "html" }
    Saves and returns the report file path.
    """
    data    = request.get_json(silent=True) or {}
    result  = data.get("result", {})
    fmt     = data.get("format", "json").lower()

    if not result:
        return jsonify({"error": "Missing 'result' field"}), 400

    from utils.reporter import save_json_report, save_html_report
    try:
        if fmt == "html":
            path = save_html_report(result)
        else:
            path = save_json_report(result)
        return jsonify({"status": "ok", "report_path": path})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ──────────────────────────────────────────────
#  API Docs endpoint
# ──────────────────────────────────────────────

@app.route("/api/docs", methods=["GET"])
def api_docs():
    """GET /api/docs — human-readable API documentation."""
    docs = {
        "service": "PhishGuard AI REST API",
        "version": "1.0.0",
        "base_url": "/api",
        "endpoints": [
            {
                "path": "/api/scan-url",
                "method": "POST",
                "description": "Scan a URL for phishing indicators",
                "body": {"url": "string (required)"},
                "response": {
                    "risk_score": "float 0–100",
                    "verdict": "Safe | Suspicious | Phishing",
                    "level": "low | medium | high",
                    "issues": "list of detected problems",
                    "ml_score": "ML model confidence (%)",
                    "rule_score": "Rule-based score (%)",
                    "features": "extracted URL features",
                },
            },
            {
                "path": "/api/scan-email",
                "method": "POST",
                "description": "Scan raw email text for phishing",
                "body": {"email": "string – full email with headers (required)"},
            },
            {
                "path": "/api/scan-html",
                "method": "POST",
                "description": "Analyse HTML page source for phishing patterns",
                "body": {"html": "string – raw HTML (required)"},
            },
            {
                "path": "/api/history",
                "method": "GET",
                "description": "Retrieve recent scan history",
                "params": {"limit": "int (default 20, max 100)"},
            },
            {
                "path": "/api/model-info",
                "method": "GET",
                "description": "Return ML model metadata",
            },
            {
                "path": "/api/report",
                "method": "POST",
                "description": "Generate JSON or HTML report from a scan result",
                "body": {"result": "scan result dict", "format": "'json' or 'html'"},
            },
            {
                "path": "/api/health",
                "method": "GET",
                "description": "Health check",
            },
        ],
        "rate_limit": f"{RATE_LIMIT_REQUESTS} requests per {RATE_LIMIT_WINDOW}s per IP",
    }
    return jsonify(docs)


# ──────────────────────────────────────────────
#  Error Handlers
# ──────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500


# ──────────────────────────────────────────────
#  Entry Point
# ──────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    logger.info("🚀 PhishGuard AI starting …")
    # Pre-load the ML model so first request isn't slow
    try:
        get_cached_model()
        logger.info("✅ ML model ready")
    except Exception as e:
        logger.warning("Could not pre-load ML model: %s", e)
    app.run(debug=True, host="0.0.0.0", port=5000)

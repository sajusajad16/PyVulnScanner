"""
utils/feature_extractor.py
--------------------------
Extracts numerical and categorical features from URLs, emails, and HTML content.
Used by both the ML model and the rule-based detection engine.
"""

import re
import math
import urllib.parse
from difflib import SequenceMatcher


# ─────────────────────────────────────────────
#  Known-legitimate domains for similarity check
# ─────────────────────────────────────────────
TRUSTED_DOMAINS = [
    "google", "facebook", "amazon", "microsoft", "apple", "paypal",
    "ebay", "netflix", "instagram", "twitter", "linkedin", "github",
    "dropbox", "spotify", "adobe", "salesforce", "oracle", "ibm",
    "cisco", "stripe", "zoom", "slack", "youtube", "wikipedia",
    "bankofamerica", "chase", "wellsfargo", "citibank", "usbank",
    "irs", "fedex", "ups", "dhl", "outlook", "office",
]

# ─────────────────────────────────────────────
#  Suspicious keywords that often appear in phishing
# ─────────────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "validate",
    "update", "upgrade", "confirm", "secure", "security", "alert",
    "account", "banking", "password", "credential", "reset", "unlock",
    "suspend", "suspended", "restore", "recover", "urgent", "immediate",
    "click", "prize", "winner", "claim", "reward", "free", "gift",
    "invoice", "payment", "billing", "refund", "tax", "irs", "gov",
    "support", "helpdesk", "customer-service", "access", "webscr",
]

# ─────────────────────────────────────────────
#  Phishing keywords specific to email content
# ─────────────────────────────────────────────
EMAIL_PHISHING_KEYWORDS = [
    "act now", "urgent", "immediately", "verify your account",
    "click here", "confirm your identity", "your account will be",
    "suspended", "limited", "unusual activity", "unauthorized access",
    "password expired", "update your information", "security alert",
    "congratulations you won", "claim your prize", "free gift",
    "wire transfer", "bank details", "social security", "ssn",
    "credit card", "billing information", "payment failed",
    "dear customer", "dear user", "valued member",
]

# ─────────────────────────────────────────────
#  Suspicious TLDs commonly used in phishing
# ─────────────────────────────────────────────
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq",   # Free Freenom TLDs
    ".xyz", ".top", ".win", ".loan",       # Cheap TLDs abused heavily
    ".ru", ".cn", ".pw", ".cc",            # High-abuse country codes
    ".info", ".biz", ".click", ".link",    # Often misused
]


# ══════════════════════════════════════════════
#  URL FEATURE EXTRACTION
# ══════════════════════════════════════════════

def extract_url_features(url: str) -> dict:
    """
    Extract a comprehensive set of features from a URL.
    Returns a dictionary of feature_name → value pairs.
    """
    features = {}
    parsed = _safe_parse(url)
    domain = parsed.netloc.lower() if parsed else ""
    path = parsed.path.lower() if parsed else ""
    query = parsed.query.lower() if parsed else ""
    full = url.lower()

    # ── Basic length features ──────────────────
    features["url_length"]    = len(url)
    features["domain_length"] = len(domain)
    features["path_length"]   = len(path)

    # ── Protocol ──────────────────────────────
    features["uses_https"]    = int(url.lower().startswith("https://"))
    features["uses_http"]     = int(url.lower().startswith("http://"))

    # ── Special character counts ───────────────
    features["count_dots"]    = url.count(".")
    features["count_hyphens"] = url.count("-")
    features["count_at"]      = url.count("@")
    features["count_slash"]   = url.count("/")
    features["count_question"]= url.count("?")
    features["count_equals"]  = url.count("=")
    features["count_ampersand"]= url.count("&")
    features["count_percent"] = url.count("%")
    features["count_underscores"] = url.count("_")

    # ── IP address as domain ───────────────────
    features["has_ip_address"] = int(bool(
        re.match(r"https?://\d{1,3}(\.\d{1,3}){3}", url)
    ))

    # ── Suspicious TLD ─────────────────────────
    features["suspicious_tld"] = int(any(domain.endswith(t) for t in SUSPICIOUS_TLDS))

    # ── Subdomain depth ────────────────────────
    # e.g. secure.paypal.login.xyz → 3 parts before TLD
    parts = domain.split(".")
    features["subdomain_depth"] = max(0, len(parts) - 2)

    # ── Suspicious keywords in URL ─────────────
    kw_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full]
    features["suspicious_keyword_count"] = len(kw_hits)
    features["suspicious_keywords"] = kw_hits  # kept for reporting

    # ── Domain similarity to trusted brands ────
    sim_result = check_domain_similarity(domain)
    features["domain_similarity_score"] = sim_result["score"]
    features["domain_similar_to"]       = sim_result["similar_to"]
    features["is_typosquatting"]        = int(sim_result["score"] > 0.75 and
                                               sim_result["similar_to"] != "")

    # ── Entropy (randomness) of domain ─────────
    features["domain_entropy"] = _shannon_entropy(domain)

    # ── Path depth ─────────────────────────────
    features["path_depth"] = path.count("/")

    # ── Encoded characters ─────────────────────
    features["has_encoded_chars"] = int("%" in url)

    # ── Double slash in path ───────────────────
    features["has_double_slash"] = int("//" in path)

    # ── Port in URL ────────────────────────────
    features["has_port"] = int(bool(re.search(r":\d{2,5}(/|$)", domain)))

    # ── Fragment presence ──────────────────────
    features["has_fragment"] = int("#" in url)

    # ── Long query string ──────────────────────
    features["query_length"] = len(query)

    # ── Digit ratio in domain ──────────────────
    digits_in_domain = sum(c.isdigit() for c in domain.replace(".", ""))
    total_domain_chars = max(1, len(domain.replace(".", "")))
    features["digit_ratio_domain"] = round(digits_in_domain / total_domain_chars, 3)

    return features


def check_domain_similarity(domain: str) -> dict:
    """
    Check whether the domain looks suspiciously similar to a trusted brand.
    Returns similarity score (0–1) and the brand it resembles most.
    """
    # Strip www. and extract base domain
    clean = re.sub(r"^www\.", "", domain)
    base  = clean.split(".")[0] if "." in clean else clean

    best_score  = 0.0
    best_match  = ""

    for brand in TRUSTED_DOMAINS:
        score = SequenceMatcher(None, base, brand).ratio()
        # Also check if brand is embedded in domain
        if brand in clean and brand != base:
            score = max(score, 0.80)
        if score > best_score:
            best_score = score
            best_match = brand

    # Exact match → legitimate (not typosquatting)
    if best_match and best_match == base:
        best_score = 1.0
        best_match = ""  # It IS the real domain

    return {
        "score":      round(best_score, 3),
        "similar_to": best_match if best_score > 0.75 else "",
    }


# ══════════════════════════════════════════════
#  EMAIL FEATURE EXTRACTION
# ══════════════════════════════════════════════

def extract_email_features(email_text: str) -> dict:
    """
    Analyse raw email text (headers + body) for phishing signals.
    """
    features = {}
    lower = email_text.lower()
    lines  = email_text.splitlines()

    # ── Header parsing ─────────────────────────
    headers, body = _split_email(email_text)

    features["has_from_header"]    = int("from:" in headers.lower())
    features["has_reply_to"]       = int("reply-to:" in headers.lower())
    features["has_return_path"]    = int("return-path:" in headers.lower())
    features["has_x_mailer"]       = int("x-mailer:" in headers.lower())
    features["has_authentication_results"] = int("authentication-results:" in headers.lower())

    # ── From / Reply-To mismatch ───────────────
    from_addr     = _extract_header_value(headers, "from")
    reply_to_addr = _extract_header_value(headers, "reply-to")
    features["from_reply_to_mismatch"] = int(
        bool(from_addr) and bool(reply_to_addr) and
        _extract_domain(from_addr) != _extract_domain(reply_to_addr)
    )

    # ── Links in body ──────────────────────────
    urls_in_body = re.findall(r"https?://[^\s<>\"']+", body)
    features["url_count_in_body"] = len(urls_in_body)
    features["has_suspicious_urls"] = int(any(
        _quick_url_phishing_check(u) for u in urls_in_body
    ))

    # ── Phishing keyword hits ──────────────────
    kw_hits = [kw for kw in EMAIL_PHISHING_KEYWORDS if kw in lower]
    features["phishing_keyword_count"] = len(kw_hits)
    features["phishing_keywords"]      = kw_hits

    # ── HTML in email ──────────────────────────
    features["is_html_email"] = int("<html" in lower or "<body" in lower)
    features["has_hidden_content"] = int(
        'display:none' in lower or 'visibility:hidden' in lower
    )

    # ── Urgency signals ────────────────────────
    urgency_words = ["urgent", "immediately", "expire", "suspended", "action required",
                     "24 hours", "48 hours", "verify now", "click now"]
    features["urgency_score"] = sum(1 for w in urgency_words if w in lower)

    # ── Generic greeting ──────────────────────
    features["generic_greeting"] = int(
        re.search(r"\bdear (customer|user|member|valued|client|sir|madam)\b", lower) is not None
    )

    # ── Spelling / grammar proxy ───────────────
    # High ratio of CAPS words can indicate spam
    words = re.findall(r"\b[A-Z]{3,}\b", email_text)
    features["all_caps_word_count"] = len(words)

    # ── Attachment signals ─────────────────────
    features["mentions_attachment"] = int(
        "attachment" in lower or "attached" in lower or ".zip" in lower or ".exe" in lower
    )

    # ── Suspicious sender domain ───────────────
    sender_domain = _extract_domain(from_addr) if from_addr else ""
    features["suspicious_sender_tld"] = int(
        any(sender_domain.endswith(t) for t in SUSPICIOUS_TLDS)
    )

    features["body_length"]   = len(body)
    features["header_length"] = len(headers)

    return features


# ══════════════════════════════════════════════
#  HTML CONTENT FEATURE EXTRACTION
# ══════════════════════════════════════════════

def extract_html_features(html: str) -> dict:
    """
    Analyse raw HTML page content for phishing signals.
    """
    features = {}
    lower = html.lower()

    # ── Form analysis ──────────────────────────
    features["form_count"]           = lower.count("<form")
    features["password_field_count"] = lower.count('type="password"') + lower.count("type='password'")
    features["hidden_input_count"]   = lower.count('type="hidden"')  + lower.count("type='hidden'")
    features["text_input_count"]     = lower.count('type="text"')    + lower.count("type='text'")

    # ── External resource loading ──────────────
    features["external_script_count"] = len(re.findall(r'<script[^>]+src=["\']https?://', lower))
    features["external_image_count"]  = len(re.findall(r'<img[^>]+src=["\']https?://', lower))
    features["iframe_count"]          = lower.count("<iframe")

    # ── Suspicious JavaScript ──────────────────
    suspicious_js = ["eval(", "document.write(", "window.location", "unescape(",
                     "fromcharcode", "base64", "atob(", "escape("]
    features["suspicious_js_count"] = sum(1 for s in suspicious_js if s in lower)

    # ── Form action targeting external domain ──
    form_actions = re.findall(r'<form[^>]+action=["\']([^"\']+)', lower)
    features["external_form_action"] = int(any(a.startswith("http") for a in form_actions))

    # ── Favicon and title ─────────────────────
    features["has_favicon"] = int("favicon" in lower)
    title_match = re.search(r"<title[^>]*>(.*?)</title>", lower)
    title_text  = title_match.group(1) if title_match else ""
    features["title_length"] = len(title_text)

    # ── Disable right-click signal ─────────────
    features["disables_right_click"] = int("contextmenu" in lower and "return false" in lower)

    # ── Pop-up or redirect signals ─────────────
    features["has_popup"] = int("window.open(" in lower or "alert(" in lower)
    features["has_redirect"] = int("window.location" in lower or "meta http-equiv=\"refresh\"" in lower)

    # ── Phishing keywords in visible text ──────
    text_only = re.sub(r"<[^>]+>", " ", html).lower()
    kw_hits   = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text_only]
    features["page_keyword_count"] = len(kw_hits)
    features["page_keywords"]      = kw_hits

    # ── Copyright year check ───────────────────
    features["has_copyright"] = int("copyright" in lower or "©" in lower)

    # ── Overall HTML size ──────────────────────
    features["html_length"] = len(html)

    return features


# ══════════════════════════════════════════════
#  ML FEATURE VECTOR (numeric only)
# ══════════════════════════════════════════════

def build_ml_feature_vector(url: str) -> list:
    """
    Returns a flat numeric feature vector from URL features,
    suitable for scikit-learn model input.
    """
    f = extract_url_features(url)
    return [
        f["url_length"],
        f["domain_length"],
        f["uses_https"],
        f["count_dots"],
        f["count_hyphens"],
        f["count_at"],
        f["count_slash"],
        f["count_question"],
        f["count_equals"],
        f["count_ampersand"],
        f["count_percent"],
        f["has_ip_address"],
        f["suspicious_tld"],
        f["subdomain_depth"],
        f["suspicious_keyword_count"],
        f["domain_similarity_score"],
        f["is_typosquatting"],
        f["domain_entropy"],
        f["path_depth"],
        f["has_encoded_chars"],
        f["has_double_slash"],
        f["has_port"],
        f["digit_ratio_domain"],
        f["query_length"],
    ]


ML_FEATURE_NAMES = [
    "url_length", "domain_length", "uses_https", "count_dots",
    "count_hyphens", "count_at", "count_slash", "count_question",
    "count_equals", "count_ampersand", "count_percent", "has_ip_address",
    "suspicious_tld", "subdomain_depth", "suspicious_keyword_count",
    "domain_similarity_score", "is_typosquatting", "domain_entropy",
    "path_depth", "has_encoded_chars", "has_double_slash", "has_port",
    "digit_ratio_domain", "query_length",
]


# ══════════════════════════════════════════════
#  HELPER FUNCTIONS
# ══════════════════════════════════════════════

def _safe_parse(url: str):
    """Parse URL safely, returning None on failure."""
    try:
        return urllib.parse.urlparse(url)
    except Exception:
        return None


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    prob = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


def _split_email(raw: str) -> tuple:
    """Split raw email into (headers, body) at the first blank line."""
    if "\n\n" in raw:
        idx = raw.index("\n\n")
        return raw[:idx], raw[idx + 2:]
    return raw, ""


def _extract_header_value(headers: str, header_name: str) -> str:
    """Extract the value of a specific email header."""
    match = re.search(rf"^{header_name}:\s*(.+)$", headers, re.IGNORECASE | re.MULTILINE)
    return match.group(1).strip() if match else ""


def _extract_domain(email_addr: str) -> str:
    """Extract domain from an email address or URL."""
    match = re.search(r"@([a-zA-Z0-9.\-]+)", email_addr)
    if match:
        return match.group(1).lower()
    parsed = _safe_parse(email_addr)
    return parsed.netloc.lower() if parsed else ""


def _quick_url_phishing_check(url: str) -> bool:
    """Fast heuristic check for suspicious URLs found in email bodies."""
    lower = url.lower()
    return (
        any(lower.endswith(t) for t in SUSPICIOUS_TLDS) or
        re.match(r"https?://\d{1,3}(\.\d{1,3}){3}", url) is not None or
        any(kw in lower for kw in ["verify", "login", "secure", "update", "account"])
    )

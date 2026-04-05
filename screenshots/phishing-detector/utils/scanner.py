"""
utils/scanner.py
----------------
High-level scanning engine.
Combines ML predictions with rule-based heuristics and
produces a unified, human-readable scan result.
"""

import re
import logging
from datetime import datetime
from utils.feature_extractor import (
    extract_url_features,
    extract_email_features,
    extract_html_features,
)

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════
#  RISK THRESHOLDS
# ══════════════════════════════════════════════

THRESHOLD_SAFE      = 30   # score < 30  → Safe
THRESHOLD_SUSPICIOUS = 60  # 30 ≤ score < 60 → Suspicious
                            # score ≥ 60 → Phishing


def score_to_verdict(score: float) -> dict:
    """Convert a numeric 0–100 risk score to a verdict dict."""
    if score < THRESHOLD_SAFE:
        return {"verdict": "Safe",       "level": "low",    "color": "green"}
    elif score < THRESHOLD_SUSPICIOUS:
        return {"verdict": "Suspicious", "level": "medium", "color": "orange"}
    else:
        return {"verdict": "Phishing",   "level": "high",   "color": "red"}


# ══════════════════════════════════════════════
#  URL SCANNER
# ══════════════════════════════════════════════

def scan_url(url: str, model_tuple=None) -> dict:
    """
    Full phishing analysis of a URL.
    Combines ML score with rule-based penalties.
    """
    issues   = []
    rule_score = 0

    # ── Extract features ──────────────────────
    features = extract_url_features(url)

    # ── Rule-based scoring ────────────────────
    if not features["uses_https"]:
        issues.append("⚠️  URL uses plain HTTP (not HTTPS)")
        rule_score += 15

    if features["has_ip_address"]:
        issues.append("🔴 Domain is a raw IP address — very suspicious")
        rule_score += 35

    if features["suspicious_tld"]:
        issues.append(f"⚠️  Suspicious top-level domain detected")
        rule_score += 20

    if features["is_typosquatting"]:
        brand = features["domain_similar_to"]
        issues.append(f"🔴 Domain looks like a fake '{brand}' (typosquatting)")
        rule_score += 40

    if features["count_at"] > 0:
        issues.append("🔴 URL contains '@' symbol — often used to mislead users")
        rule_score += 25

    if features["subdomain_depth"] >= 3:
        issues.append(f"⚠️  Unusually deep subdomain structure ({features['subdomain_depth']} levels)")
        rule_score += 15

    if features["suspicious_keyword_count"] >= 3:
        kws = ", ".join(features["suspicious_keywords"][:5])
        issues.append(f"⚠️  Multiple suspicious keywords: {kws}")
        rule_score += 20
    elif features["suspicious_keyword_count"] >= 1:
        kws = ", ".join(features["suspicious_keywords"])
        issues.append(f"ℹ️  Suspicious keyword(s) found: {kws}")
        rule_score += 10

    if features["url_length"] > 100:
        issues.append(f"ℹ️  URL is unusually long ({features['url_length']} characters)")
        rule_score += 10

    if features["has_double_slash"]:
        issues.append("⚠️  Double-slash found in path — potential redirect obfuscation")
        rule_score += 15

    if features["has_port"]:
        issues.append("⚠️  Non-standard port detected in URL")
        rule_score += 10

    if features["digit_ratio_domain"] > 0.4:
        issues.append("ℹ️  High ratio of digits in domain name")
        rule_score += 10

    if features["domain_entropy"] > 3.8:
        issues.append(f"ℹ️  High domain entropy ({features['domain_entropy']:.2f}) — random-looking domain")
        rule_score += 10

    # ── ML prediction ─────────────────────────
    ml_result = {"ml_score": 0, "confidence": 0, "feature_importances": []}
    try:
        from model import predict_url
        ml_result = predict_url(url, model_tuple)
    except Exception as e:
        logger.warning("ML prediction failed: %s", e)

    # ── Combine scores (60% ML + 40% rules) ───
    ml_score   = ml_result["confidence"]           # 0–100
    rule_score = min(rule_score, 100)
    combined   = round(0.60 * ml_score + 0.40 * rule_score, 1)

    verdict = score_to_verdict(combined)

    return {
        "type":        "url",
        "target":      url,
        "risk_score":  combined,
        "ml_score":    round(ml_score, 1),
        "rule_score":  rule_score,
        **verdict,
        "issues":      issues,
        "features":    {k: v for k, v in features.items()
                        if k not in ("suspicious_keywords", "domain_similar_to")},
        "feature_importances": ml_result.get("feature_importances", []),
        "scanned_at":  datetime.utcnow().isoformat(),
    }


# ══════════════════════════════════════════════
#  EMAIL SCANNER
# ══════════════════════════════════════════════

def scan_email(email_text: str, model_tuple=None) -> dict:
    """
    Full phishing analysis of raw email content.
    """
    issues     = []
    rule_score = 0

    features = extract_email_features(email_text)

    # ── Rule-based scoring ────────────────────
    if features["from_reply_to_mismatch"]:
        issues.append("🔴 'From' and 'Reply-To' domains don't match — likely spoofed")
        rule_score += 35

    if features["generic_greeting"]:
        issues.append("⚠️  Generic greeting used (e.g. 'Dear Customer') — typical phishing tactic")
        rule_score += 20

    if features["urgency_score"] >= 3:
        issues.append(f"🔴 High urgency language detected ({features['urgency_score']} signals)")
        rule_score += 25
    elif features["urgency_score"] >= 1:
        issues.append(f"⚠️  Urgency language detected")
        rule_score += 10

    if features["phishing_keyword_count"] >= 4:
        kws = ", ".join(features["phishing_keywords"][:6])
        issues.append(f"🔴 Many phishing keywords: {kws}")
        rule_score += 30
    elif features["phishing_keyword_count"] >= 2:
        kws = ", ".join(features["phishing_keywords"])
        issues.append(f"⚠️  Phishing keywords found: {kws}")
        rule_score += 15

    if features["has_suspicious_urls"]:
        issues.append("🔴 Suspicious URLs found in email body")
        rule_score += 30

    if features["suspicious_sender_tld"]:
        issues.append("🔴 Sender domain uses a suspicious TLD")
        rule_score += 25

    if features["has_hidden_content"]:
        issues.append("🔴 Hidden content detected (display:none / visibility:hidden)")
        rule_score += 20

    if features["all_caps_word_count"] > 10:
        issues.append(f"ℹ️  Excessive use of ALL CAPS ({features['all_caps_word_count']} words)")
        rule_score += 10

    if features["mentions_attachment"]:
        issues.append("⚠️  Email mentions attachments — be cautious about opening files")
        rule_score += 10

    if not features["has_authentication_results"]:
        issues.append("ℹ️  No SPF/DKIM authentication headers found")
        rule_score += 5

    # ── Scan all URLs found in body via URL scanner ──
    urls_in_body = re.findall(r"https?://[^\s<>\"']+", email_text)
    url_results  = []
    for u in urls_in_body[:5]:  # cap at 5 to avoid slowness
        try:
            url_scan = scan_url(u, model_tuple)
            url_results.append({
                "url":        u,
                "risk_score": url_scan["risk_score"],
                "verdict":    url_scan["verdict"],
            })
            if url_scan["risk_score"] >= 60:
                rule_score = min(rule_score + 10, 100)
        except Exception:
            pass

    rule_score = min(rule_score, 100)
    verdict    = score_to_verdict(rule_score)

    return {
        "type":       "email",
        "risk_score": rule_score,
        **verdict,
        "issues":     issues,
        "features":   {k: v for k, v in features.items()
                       if k not in ("phishing_keywords",)},
        "url_scans":  url_results,
        "scanned_at": datetime.utcnow().isoformat(),
    }


# ══════════════════════════════════════════════
#  HTML SCANNER
# ══════════════════════════════════════════════

def scan_html(html: str, model_tuple=None) -> dict:
    """
    Full phishing analysis of HTML page source.
    """
    issues     = []
    rule_score = 0

    features = extract_html_features(html)

    # ── Rule-based scoring ────────────────────
    if features["password_field_count"] > 0 and features["form_count"] > 0:
        issues.append("🔴 Page contains a login form with password field")
        rule_score += 30

    if features["hidden_input_count"] > 3:
        issues.append(f"⚠️  Many hidden form inputs ({features['hidden_input_count']}) — could be data harvesting")
        rule_score += 20

    if features["external_form_action"]:
        issues.append("🔴 Form submits data to an external domain")
        rule_score += 35

    if features["iframe_count"] > 0:
        issues.append(f"⚠️  Page contains {features['iframe_count']} iframe(s) — possible clickjacking")
        rule_score += 15

    if features["suspicious_js_count"] >= 3:
        issues.append(f"🔴 Multiple suspicious JavaScript patterns ({features['suspicious_js_count']})")
        rule_score += 25
    elif features["suspicious_js_count"] >= 1:
        issues.append("⚠️  Suspicious JavaScript detected (eval, base64, etc.)")
        rule_score += 10

    if features["disables_right_click"]:
        issues.append("⚠️  Page disables right-click — common in phishing pages")
        rule_score += 10

    if features["has_redirect"]:
        issues.append("ℹ️  Page contains a redirect mechanism")
        rule_score += 10

    if features["has_popup"]:
        issues.append("ℹ️  Page uses pop-up dialogs")
        rule_score += 5

    if features["page_keyword_count"] >= 4:
        kws = ", ".join(features["page_keywords"][:5])
        issues.append(f"⚠️  Multiple phishing-related keywords in page content: {kws}")
        rule_score += 15

    if not features["has_copyright"]:
        issues.append("ℹ️  No copyright notice found — may be a hastily made fake page")
        rule_score += 5

    rule_score = min(rule_score, 100)
    verdict    = score_to_verdict(rule_score)

    return {
        "type":       "html",
        "risk_score": rule_score,
        **verdict,
        "issues":     issues,
        "features":   {k: v for k, v in features.items()
                       if k not in ("page_keywords",)},
        "scanned_at": datetime.utcnow().isoformat(),
    }

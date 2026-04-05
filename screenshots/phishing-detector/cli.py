#!/usr/bin/env python3
"""
cli.py
------
PhishGuard AI – Command Line Interface
Scan URLs, emails, and HTML files directly from the terminal.

Usage:
  python cli.py url   "https://suspicious-site.com"
  python cli.py email path/to/email.txt
  python cli.py html  path/to/page.html
  python cli.py train
  python cli.py history
"""

import sys
import json
import argparse
import textwrap
from datetime import datetime


# ══════════════════════════════════════════════
#  Terminal Colors
# ══════════════════════════════════════════════

class C:
    RED     = "\033[91m"
    ORANGE  = "\033[93m"
    GREEN   = "\033[92m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

def colored(text, *codes):
    return "".join(codes) + str(text) + C.RESET

def verdict_color(verdict: str) -> str:
    return {
        "Safe":       C.GREEN,
        "Suspicious": C.ORANGE,
        "Phishing":   C.RED,
    }.get(verdict, C.CYAN)


# ══════════════════════════════════════════════
#  Output Formatters
# ══════════════════════════════════════════════

BANNER = f"""{C.CYAN}{C.BOLD}
  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
{C.RESET}{C.DIM}  AI-Powered Phishing Detection Tool  v1.0.0{C.RESET}
"""

def print_banner():
    print(BANNER)

def print_separator(char="─", width=70):
    print(colored(char * width, C.DIM))

def print_result(result: dict):
    """Pretty-print a scan result to the terminal."""
    verdict = result.get("verdict", "Unknown")
    score   = result.get("risk_score", 0)
    vc      = verdict_color(verdict)

    print_separator()
    print(f"  {colored('VERDICT:', C.BOLD)}  {colored(verdict.upper(), vc, C.BOLD)}")
    print(f"  {colored('RISK SCORE:', C.BOLD)} {colored(f'{score:.1f} / 100', vc, C.BOLD)}")

    if result.get("target"):
        print(f"  {colored('TARGET:', C.BOLD)}   {result['target'][:80]}")

    print(f"  {colored('ML SCORE:', C.BOLD)}  {result.get('ml_score', 'N/A')}%   "
          f"{colored('RULE SCORE:', C.BOLD)} {result.get('rule_score', 'N/A')}%")
    print(f"  {colored('SCANNED:', C.BOLD)}   {result.get('scanned_at', '')[:19]} UTC")
    if result.get("duration_ms"):
        print(f"  {colored('DURATION:', C.BOLD)}  {result['duration_ms']} ms")

    print_separator()
    issues = result.get("issues", [])
    if issues:
        print(colored("  ⚠  DETECTED ISSUES:", C.BOLD))
        for iss in issues:
            print(f"     {iss}")
    else:
        print(colored("  ✅ No issues detected", C.GREEN))

    fi = result.get("feature_importances", [])
    if fi:
        print_separator("·")
        print(colored("  📊 TOP ML FEATURES:", C.BOLD))
        for item in fi:
            bar = "█" * int(item["importance"] * 40)
            print(f"     {item['feature']:<30} {colored(bar, C.CYAN)} {item['importance']:.4f}")

    print_separator()


# ══════════════════════════════════════════════
#  CLI Commands
# ══════════════════════════════════════════════

def cmd_scan_url(args):
    """Scan one or more URLs."""
    from utils.scanner import scan_url
    from model import get_model
    model = get_model()

    for url in args.target:
        print(f"\n{colored('🔍 Scanning URL:', C.BOLD)} {url}")
        try:
            result = scan_url(url.strip(), model)
            print_result(result)

            if args.json:
                print(json.dumps(result, indent=2, default=str))

            if args.report:
                fmt = "html" if args.report == "html" else "json"
                if fmt == "html":
                    from utils.reporter import save_html_report
                    path = save_html_report(result)
                else:
                    from utils.reporter import save_json_report
                    path = save_json_report(result)
                print(colored(f"  📄 Report saved: {path}", C.CYAN))

        except Exception as e:
            print(colored(f"  ❌ Error: {e}", C.RED))


def cmd_scan_email(args):
    """Scan an email file."""
    from utils.scanner import scan_email
    from model import get_model
    model = get_model()

    path = args.target[0]
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            email_text = f.read()
    except FileNotFoundError:
        print(colored(f"File not found: {path}", C.RED))
        sys.exit(1)

    print(f"\n{colored('📧 Scanning email:', C.BOLD)} {path}")
    result = scan_email(email_text, model)
    print_result(result)

    if args.json:
        print(json.dumps(result, indent=2, default=str))

    if args.report:
        fmt = "html" if args.report == "html" else "json"
        if fmt == "html":
            from utils.reporter import save_html_report
            path = save_html_report(result)
        else:
            from utils.reporter import save_json_report
            path = save_json_report(result)
        print(colored(f"  📄 Report saved: {path}", C.CYAN))


def cmd_scan_html(args):
    """Scan an HTML file."""
    from utils.scanner import scan_html

    path = args.target[0]
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            html = f.read()
    except FileNotFoundError:
        print(colored(f"File not found: {path}", C.RED))
        sys.exit(1)

    print(f"\n{colored('🌐 Scanning HTML:', C.BOLD)} {path}")
    result = scan_html(html)
    print_result(result)

    if args.json:
        print(json.dumps(result, indent=2, default=str))


def cmd_train(args):
    """Re-train the ML model."""
    print(colored("\n🤖 Training ML model …", C.CYAN, C.BOLD))
    from model import train_model
    model, scaler = train_model(save=True)
    print(colored("✅ Model trained and saved successfully!", C.GREEN, C.BOLD))


def cmd_history(args):
    """Show recent scan history from the database."""
    import sqlite3
    DB_PATH = "logs/scan_history.db"
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"SELECT * FROM scans ORDER BY id DESC LIMIT {args.limit}"
        ).fetchall()
        conn.close()
    except Exception as e:
        print(colored(f"Could not read history: {e}", C.RED))
        return

    if not rows:
        print("No scan history found.")
        return

    print_separator()
    print(colored(f"  {'ID':<5} {'TYPE':<8} {'VERDICT':<12} {'SCORE':<8} {'SCANNED AT':<22} TARGET", C.BOLD))
    print_separator()
    for r in rows:
        vc    = verdict_color(r["verdict"] or "")
        score = f"{r['risk_score']:.1f}" if r["risk_score"] is not None else "N/A"
        tgt   = (r["target"] or "")[:40]
        print(f"  {r['id']:<5} {r['scan_type']:<8} "
              f"{colored(r['verdict'] or 'N/A', vc):<20} "
              f"{score:<8} {r['scanned_at'][:19]:<22} {tgt}")
    print_separator()


# ══════════════════════════════════════════════
#  Argument Parser
# ══════════════════════════════════════════════

def build_parser():
    parser = argparse.ArgumentParser(
        prog="phishguard",
        description="PhishGuard AI – Command Line Phishing Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Examples:
              python cli.py url "https://suspicious.example.com" --report html
              python cli.py url "http://g00gle.com" "http://faceb00k.tk"
              python cli.py email samples/phishing_email.txt
              python cli.py html  samples/fake_login.html --json
              python cli.py train
              python cli.py history --limit 10
        """),
    )
    sub = parser.add_subparsers(dest="command")

    # url
    p_url = sub.add_parser("url", help="Scan one or more URLs")
    p_url.add_argument("target", nargs="+", help="URL(s) to scan")
    p_url.add_argument("--json",   action="store_true", help="Output raw JSON")
    p_url.add_argument("--report", choices=["json", "html"], help="Generate a report file")

    # email
    p_email = sub.add_parser("email", help="Scan an email file")
    p_email.add_argument("target", nargs=1, help="Path to email .txt file")
    p_email.add_argument("--json",   action="store_true")
    p_email.add_argument("--report", choices=["json", "html"])

    # html
    p_html = sub.add_parser("html", help="Scan an HTML file")
    p_html.add_argument("target", nargs=1, help="Path to HTML file")
    p_html.add_argument("--json",   action="store_true")
    p_html.add_argument("--report", choices=["json", "html"])

    # train
    sub.add_parser("train", help="Re-train the ML model")

    # history
    p_hist = sub.add_parser("history", help="Show recent scan history")
    p_hist.add_argument("--limit", type=int, default=20, help="Number of records (default 20)")

    return parser


# ══════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════

def main():
    print_banner()
    parser = build_parser()
    args   = parser.parse_args()

    if args.command == "url":
        cmd_scan_url(args)
    elif args.command == "email":
        cmd_scan_email(args)
    elif args.command == "html":
        cmd_scan_html(args)
    elif args.command == "train":
        cmd_train(args)
    elif args.command == "history":
        cmd_history(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

import os
from datetime import datetime

def generate_html_report(data, target):
    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"reports/report_{target}_{timestamp}.html"

    html = f"""
    <html>
    <head>
        <title>ReconX Report - {target}</title>
        <style>
            body {{
                font-family: Arial;
                background: #0d1117;
                color: #c9d1d9;
                padding: 20px;
            }}
            h1 {{ color: #58a6ff; }}
            h2 {{ color: #79c0ff; }}
            .box {{
                background: #161b22;
                padding: 15px;
                border-radius: 10px;
                margin-bottom: 20px;
            }}
        </style>
    </head>

    <body>
        <h1>ReconX Scan Report</h1>
        <p><b>Target:</b> {target}</p>
        <p><b>Date:</b> {timestamp}</p>

        <div class="box">
            <h2>Subdomains</h2>
            <ul>
                {''.join(f"<li>{s}</li>" for s in (data.get('subdomains') or ["No results"]))}
            </ul>
        </div>

        <div class="box">
            <h2>Open Ports</h2>
            <ul>
                {''.join(f"<li>{p}</li>" for p in (data.get('ports') or ["No results"]))}
            </ul>
        </div>

        <div class="box">
            <h2>Directories</h2>
            <ul>
                {''.join(f"<li>{d}</li>" for d in (data.get('directories') or ["No results"]))}
            </ul>
        </div>

        <div class="box">
            <h2>Vulnerabilities</h2>
            <ul>
                {''.join(f"<li>{v}</li>" for v in (data.get('vulnerabilities') or ["No vulnerabilities"]))}
            </ul>
        </div>

        <div class="box">
            <h2>Discovered Parameters</h2>
            <ul>
                {''.join(f"<li>{p}</li>" for p in (data.get('parameters') or ["No parameters"]))}
            </ul>
        </div>

        <div class="box">
            <h2>Fuzzing Results</h2>
            <ul>
                {''.join(f"<li>{f}</li>" for f in (data.get('fuzzing') or ["No issues"]))}
            </ul>
        </div>

    </body>
    </html>
    """

    with open(filename, "w") as f:
        f.write(html)

    print(f"[+] HTML Report saved: {filename}")

def save_report(data):
    with open("report.html", "w") as f:
        f.write("""
        <html>
        <head>
            <title>ReconX Report</title>
            <style>
                body {
                    background-color: #0d1117;
                    color: #c9d1d9;
                    font-family: Arial;
                    padding: 20px;
                }
                h1 { color: #58a6ff; }
                h2 { color: #79c0ff; }
                .card {
                    background: #161b22;
                    padding: 15px;
                    margin: 10px 0;
                    border-radius: 10px;
                }
                .port { color: #3fb950; }
                .dir { color: #58a6ff; }
                .vuln { color: #f85149; }
            </style>
        </head>
        <body>
        """)

        f.write("<h1>🚀 ReconX Report</h1>")
        f.write(f"<h2>Target: {data['target']}</h2>")

        # Ports
        f.write("<div class='card'><h3>🔓 Open Ports</h3><ul>")
        for p in data["open_ports"]:
            f.write(f"<li class='port'>Port {p}</li>")
        f.write("</ul></div>")

        # Banners
        f.write("<div class='card'><h3>🛰 Service Banners</h3><ul>")
        for port, banner in data["banners"].items():
            f.write(f"<li>Port {port}: {banner}</li>")
        f.write("</ul></div>")

        # Directories
        f.write("<div class='card'><h3>📂 Directories</h3><ul>")
        for d in data["directories"]:
            f.write(f"<li class='dir'>{d}</li>")
        f.write("</ul></div>")

        # Vulnerabilities
        f.write("<div class='card'><h3>⚠ Vulnerabilities</h3><ul>")
        if data["vulnerabilities"]:
            for v in data["vulnerabilities"]:
                f.write(f"<li class='vuln'>{v}</li>")
        else:
            f.write("<li>No vulnerabilities found</li>")
        f.write("</ul></div>")

        f.write("</body></html>")

    print("\n[+] Report saved as report.html")

from flask import Flask, request, redirect, url_for
from datetime import datetime
import logging
import urllib.parse
import time

app = Flask(__name__)

# ---------------- LOGGING ----------------
logging.basicConfig(
    filename="sentinelshield.log",
    level=logging.INFO,
    format="%(asctime)s | %(message)s"
)

# ---------------- RATE LIMIT ----------------
REQUEST_LIMIT = 5
TIME_WINDOW = 60
ip_tracker = {}

# Track abusive IPs
abusive_ips = {}

# ---------------- HOME ----------------
@app.route("/")
def home():
    ip = request.remote_addr
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log = f"{timestamp} | IP: {ip} | Query: / | Status: Normal | Category: None"
    logging.info(log)

    return "SentinelShield is running!"

# ---------------- INSPECT ----------------
@app.route("/inspect")
def inspect():
    ip = request.remote_addr
    query = urllib.parse.unquote(request.full_path)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    now = time.time()

    # ---- Rate limit tracking ----
    if ip not in ip_tracker:
        ip_tracker[ip] = {"count": 1, "start": now}
    else:
        if now - ip_tracker[ip]["start"] <= TIME_WINDOW:
            ip_tracker[ip]["count"] += 1
        else:
            ip_tracker[ip] = {"count": 1, "start": now}

    # ---- Attack signatures ----
    signatures = {
        "XSS": ["<script>"],
        "SQL Injection": ["select", "union", "or 1=1"],
        "Directory Traversal": ["../"],
        "Command Injection": ["cmd", "powershell"]
    }

    status = "Normal"
    category = "None"

    for attack, keys in signatures.items():
        for k in keys:
            if k.lower() in query.lower():
                status = "Malicious"
                category = attack
                break

    # ---- Rate limit violation ----
    if ip_tracker[ip]["count"] > REQUEST_LIMIT:
        status = "Malicious"
        category = "Rate Limiting / Brute Force"
        abusive_ips[ip] = abusive_ips.get(ip, 0) + 1

    log = f"{timestamp} | IP: {ip} | Query: {query} | Status: {status} | Category: {category}"
    logging.info(log)

    # ---- Return HTML page for better visualization ----
    return f"""
    <html>
        <head>
            <title>SentinelShield Inspection Result</title>
            <style>
                body {{
                    font-family: Consolas, monospace;
                    background-color: #0b1b3a;
                    color: #e6f0ff;
                    padding: 50px;
                }}
                h1 {{
                    text-align: center;
                    color: #7dd3ff;
                    font-size: 48px;
                    margin-bottom: 40px;
                }}
                .status {{
                    font-size: 24px;
                    margin: 20px 0;
                }}
                .malicious {{
                    color: #ff5f7a;
                    font-weight: bold;
                }}
                .normal {{
                    color: #6dff9e;
                    font-weight: bold;
                }}
                p {{
                    font-size: 20px;
                }}
            </style>
        </head>
        <body>
            <h1>SentinelShield Inspection</h1>
            <p>Timestamp: {timestamp}</p>
            <p>IP: {ip}</p>
            <p>Query: {query}</p>
            <p class="status">Status: <span class="{ 'malicious' if status=='Malicious' else 'normal' }">{status}</span></p>
            <p>Category: {category}</p>
        </body>
    </html>
    """

# ---------------- SOC DASHBOARD ----------------
@app.route("/summary")
def summary():
    # ---- Popup fix: redirect if query string exists ----
    if request.query_string:
        return redirect(url_for("summary"))

    data = {
        "total": 0,
        "normal": 0,
        "malicious": 0,
        "categories": {},
        "last": [],
        "top_abusers": []
    }

    try:
        with open("sentinelshield.log") as f:
            logs = [l for l in f if "Status:" in l]

        data["total"] = len(logs)

        for l in logs:
            if "Status: Normal" in l:
                data["normal"] += 1
            else:
                data["malicious"] += 1
                c = l.split("Category:")[1].strip()
                data["categories"][c] = data["categories"].get(c, 0) + 1

        data["last"] = logs[-50:]

    except FileNotFoundError:
        pass

    # ---- Top 3 abusive IPs ----
    data["top_abusers"] = sorted(
        abusive_ips.items(),
        key=lambda x: x[1],
        reverse=True
    )[:3]

    # ---- Existing HTML content ----
    return f"""
    <html>
    <head>
        <title>SentinelShield SOC</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        
        <style>
            body {{
                margin: 0;
                font-family: Segoe UI, Consolas, monospace;
                background: radial-gradient(circle at top, #0b1b3a, #02040a 65%);
                color: #e6f0ff;
            }}
            h1 {{
                text-align: center;
                margin: 40px 0;
                font-size: 52px;
                color: #7dd3ff;
                text-shadow: 0 0 18px rgba(125,211,255,0.9);
            }}
            h3 {{ font-size: 28px; color: #ffffff; }}
            .stats {{
                max-width: 1500px;
                margin: auto;
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                gap: 32px;
            }}
            .card {{
                background: rgba(10, 25, 55, 0.6);
                backdrop-filter: blur(12px);
                border-radius: 20px;
                padding: 40px;
                border: 1px solid rgba(125,211,255,0.3);
                box-shadow: 0 0 40px rgba(125,211,255,0.35);
                text-align: center;
            }}
            .card p {{ font-size: 48px; margin-top: 12px; font-weight: 600; }}
            .charts {{
                max-width: 1500px;
                margin: 90px auto;
                display: flex;
                flex-direction: column;
                gap: 90px;
            }}
            .chart-box {{
                background: rgba(8, 20, 45, 0.7);
                border-radius: 22px;
                padding: 50px;
                border: 1px solid rgba(125,211,255,0.35);
                box-shadow: 0 0 70px rgba(125,211,255,0.45);
            }}
            canvas {{ width: 100% !important; height: 560px !important; }}
            .logs {{
                max-width: 1500px;
                margin: auto;
            }}
            .pre-scrollable {{
                background: rgba(2, 6, 18, 0.95);
                border-radius: 18px;
                padding: 32px;
                color: #00ff66;
                border: 1px solid rgba(155,255,191,0.45);
                box-shadow: 0 0 40px rgba(155,255,191,0.35);
                font-size: 25px;
                line-height: 1.6; 
                max-height: 300px;
                max-width: 100%;
                overflow-y: scroll;
                overflow-x: scroll;
                white-space: pre;
                word-break: normal;
            }}
            footer {{
                text-align: center;
                margin: 50px 0;
                font-size: 18px;
                color: #8faaff;
            }}
        </style>
    </head>

    <body>

        <h1>🛡 SentinelShield Dashboard 🛡</h1>

        <div class="stats">
            <div class="card"><h3>Total Events</h3><p>{data["total"]}</p></div>
            <div class="card"><h3>Normal Traffic</h3><p style="color:#6dff9e">{data["normal"]}</p></div>
            <div class="card"><h3>Malicious Traffic</h3><p style="color:#ff5f7a">{data["malicious"]}</p></div>
        </div>

        <div class="charts">
            <div class="chart-box"><canvas id="pie"></canvas></div>
            <div class="chart-box"><canvas id="bar"></canvas></div>
        </div>

        <div class="logs">
            <h3>🚨 Top Abusive IPs</h3>
            <pre class="pre-scrollable">
{"".join([f"{ip} → {count} violations\n" for ip, count in data["top_abusers"]]) or "No abusive IPs detected yet."}
            </pre>
            <p style="font-size:15px; color:#cbd5ff; margin-top:10px;">
IPs are marked abusive only after exceeding rate-limit threshold.
</p>

            <h3>Recent Security Events</h3>
            <pre class="pre-scrollable">{"".join(data["last"])}</pre>
        </div>

        <footer>SentinelShield • Advanced IDS & Web Protection Simulation</footer>

        <script>
            new Chart(document.getElementById("pie"), {{
                type: "pie",
                data: {{
                    labels: ["Normal", "Malicious"],
                    datasets: [{{
                        data: [{data["normal"]}, {data["malicious"]}],
                        backgroundColor: ["#6dff9e", "#ff5f7a"]
                    }}]
                }},
                options: {{
                    maintainAspectRatio: false,
                    animation: {{ duration: 1800 }},
                    plugins: {{
                        title: {{
                            display: true,
                            text: "Traffic Classification",
                            color: "#ffffff",
                            font: {{ size: 30 }}
                        }},
                        legend: {{
                            labels: {{ color: "#ffffff", font: {{ size: 18 }} }}
                        }}
                    }}
                }}
            }});

            new Chart(document.getElementById("bar"), {{
                type: "bar",
                data: {{
                    labels: {list(data["categories"].keys())},
                    datasets: [{{
                        label: "Detected Attacks",
                        data: {list(data["categories"].values())},
                        backgroundColor: "#7dd3ff"
                    }}]
                }},
                options: {{
                    maintainAspectRatio: false,
                    animation: {{ duration: 1800 }},
                    plugins: {{
                        title: {{
                            display: true,
                            text: "Attack Distribution",
                            color: "#ffffff",
                            font: {{ size: 30 }}
                        }},
                        legend: {{
                            labels: {{ color: "#ffffff", font: {{ size: 18 }} }}
                        }}
                    }},
                    scales: {{
                        x: {{ ticks: {{ color: "#ffffff", font: {{ size: 18 }} }} }},
                        y: {{
                            ticks: {{ color: "#ffffff", font: {{ size: 18 }} }},
                            beginAtZero: true
                        }}
                    }}
                }}
            }});
        </script>

    </body>
    </html>
    """

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)

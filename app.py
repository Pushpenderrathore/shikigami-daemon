from flask import Flask, render_template, redirect
import json, os
from datetime import datetime

app = Flask(__name__)
ALERT_LOG = "logs/alerts.json"

def load_alerts():
    if not os.path.exists(ALERT_LOG): return []
    with open(ALERT_LOG, "r") as f: return json.load(f)

def save_alerts(alerts):
    with open(ALERT_LOG, "w") as f: json.dump(alerts, f, indent=4)

@app.route("/")
def index():
    alerts = load_alerts()
    return render_template("index.html", alerts=alerts)

@app.route("/unblock/<ip>")
def unblock(ip):
    os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
    return redirect("/")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)


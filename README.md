# 🧠 Shikigami AI - Intrusion Detection & Protection

**Shikigami AI** is an AI-powered daemon designed to monitor logs and detect suspicious activity using intelligent pattern detection.

> This tool runs as a systemd service on Linux and analyzes logs using `log_guard.py` with AI-based heuristics to scan logs for malicious behavior in real-time..

---

## 📦 Features

- 🔍 Log monitoring with AI
- 🛡️ Detects system anomalies
- 🧠 Uses a `.modelfile` to identify malicious patterns
- 🚀 Automatically starts with systemd
- 📊 CLI/Web interface support (`shikigami_app.py`)

---

## 📁 Project Structure

```bash
shikigami-ai/
├── shikigami.sh          # Startup script
├── shikigami.service     # systemd unit
├── log_guard.py          # Main detection logic (AI-powered)
├── shikigami.modelfile   # Model used for pattern detection
├── shikigami_app.py      # Optional interface (CLI/Web)
├── shikigami_logs.txt    # Output logs
├── logs/                 # Log storage
├── static/               # Static files (web)
├── templates/            # HTML templates (web)
├── requirements.txt      # Python dependencies
└── install.sh            # Quick installer


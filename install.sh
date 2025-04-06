# 1. Clone the repository
git clone https://github.com/yourname/shikigami-ai.git
cd shikigami-ai

# 2. Make scripts executable
chmod +x install.sh shikigami.sh

# 3. Run the installer (sets up virtualenv, installs requirements, sets systemd service)
sudo ./install.sh

# 4. Enable and start the service
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable shikigami.service
sudo systemctl start shikigami.service

# 5 Check service status
sudo systemctl status shikigami.service

# 6 View logs
cat /var/log/shikigami.log

# Test detection (e.g., brute force, anomaly patterns)
# Try SSH brute force, or simulate a log entry that matches a pattern from your .modelfile. If detected, it will be logged and optionally blocked

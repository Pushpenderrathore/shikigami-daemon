#!/bin/bash

PYTHON_SCRIPT="/opt/shikigami/log_guard.py"
LOG_FILE="/var/log/shikigami.log"

# Create the log file if it doesn't exist
if [ ! -f "$LOG_FILE" ]; then
  sudo touch "$LOG_FILE"
  sudo chmod 644 "$LOG_FILE"
fi

echo "$(date) - [🚀] Running Shikigami Script" >> "$LOG_FILE"
echo "$(date) - [👹] Shikigami Activated" >> "$LOG_FILE"

# Run the Python script and replace the shell with it
exec /usr/bin/python3 "$PYTHON_SCRIPT" >> "$LOG_FILE" 2>&1

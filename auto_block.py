import subprocess
import re
import os
from datetime import datetime

log_file_path = "/var/log/auth.log"  # or your custom log file

def analyze_and_act(log_entry):
    prompt = f"""
    You are a cybersecurity AI assistant.

    Analyze the following system log entry and answer in this format:

    1. Suspicious (Yes/No):
    2. Why:
    3. Should Block IP (Yes/No):
    4. Severity (Low, Medium, High, Critical):

    Log:
    {log_entry}
    """

    result = subprocess.run(
        ['ollama', 'run', 'cyberguard'],
        input=prompt.encode(),
        capture_output=True
    )

    response = result.stdout.decode()
    print(f"\n🧠 AI Response:\n{response}")

    # Log the response
    with open("cyberguard_logs.txt", "a") as f:
        f.write(f"{datetime.now()} - LOG: {log_entry}\nRESPONSE:\n{response}\n{'-'*50}\n")

    # Check for block action
    if "Suspicious: Yes" in response or "Block IP: Yes" in response:
        match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', log_entry)
        if match:
            ip = match.group(1)
            print(f"[!] Blocking suspicious IP: {ip}")
            os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")

# ========== MAIN MONITOR LOOP ==========
with open(log_file_path, "r") as log_file:
    print("🚨 Monitoring logs...")
    for line in log_file:
        if "Failed password" in line or "authentication failure" in line:
            analyze_and_act(line.strip())


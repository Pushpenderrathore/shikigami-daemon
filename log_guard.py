import subprocess
import re
import os
import time

LOG_FILES = [
    "/var/log/secure",     # For RHEL/Fedora/Arch
    "/var/log/auth.log"    # For Debian/Ubuntu
]

def follow(file_path):
    with open(file_path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.strip()

def analyze_log(log_input):
    prompt = f"""
You are a cybersecurity AI assistant.

Analyze the following system log entry and answer in this format:

1. Suspicious (Yes/No):
2. Why:
3. Should Block IP (Yes/No):
4. Severity (Low, Medium, High, Critical):

Log:
{log_input}
"""

    result = subprocess.run(
        ['ollama', 'run', 'cyberguard'],
        input=prompt.encode(),
        capture_output=True
    )

    response = result.stdout.decode()
    print("\nAI Says:\n")
    print(response)

    # Log it to file
    with open("cyberguard_logs.txt", "a") as f:
        f.write(f"LOG: {log_input}\nRESPONSE: {response}\n\n")

    # Auto-block if flagged
    if "Suspicious: Yes" in response or "Block IP: Yes" in response:
        match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', log_input)
        if match:
            ip = match.group(1)
            print(f"[!] Blocking IP: {ip}")
            os.system(f'sudo iptables -A INPUT -s {ip} -j DROP')

# ---------- Main logic ----------
def main():
    log_found = False
    for file in LOG_FILES:
        if os.path.exists(file):
            print(f"📡 Monitoring: {file}")
            log_found = True
            for line in follow(file):
                if "Failed password" in line or "authentication failure" in line:
                    analyze_log(line)
            break

    if not log_found:
        print("❌ No supported log file found. Exiting.")

if __name__ == "__main__":
    main()


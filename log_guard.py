import subprocess
import re
import os
import time

# Supported log files
LOG_FILES = [
    "/var/log/secure",     # RHEL, CentOS, Fedora, Arch
    "/var/log/auth.log"    # Ubuntu, Debian
]

def follow(file_path):
    """Tail the file live (like tail -f)"""
    with open(file_path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.strip()

def block_ip(ip):
    """Block the IP using iptables"""
    print(f"[!] Blocking IP: {ip}")
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")

def analyze_log_entry(log_input):
    """Send log input to Ollama model and return the response"""
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

    return result.stdout.decode()

def parse_response(response, log_input):
    """Check if IP should be blocked, and log it"""
    should_block = "Suspicious: Yes" in response or "Block IP: Yes" in response
    blocked_ips = []

    if should_block:
        match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', log_input)
        if match:
            ip = match.group(1)
            block_ip(ip)
            blocked_ips.append(ip)

    # Save log + response
    with open("cyberguard_logs.txt", "a") as f:
        f.write(f"LOG: {log_input}\nRESPONSE: {response}\n\n")

    return blocked_ips

def main():
    log_found = False
    for log_file in LOG_FILES:
        if os.path.exists(log_file):
            print(f"📡 Monitoring: {log_file}")
            log_found = True
            for line in follow(log_file):
                if any(keyword in line for keyword in ["Failed password", "authentication failure", "invalid user", "session opened", "sudo"]):
                    response = analyze_log_entry(line)
                    print("\nAI Says:\n", response)
                    parse_response(response, line)
            break

    if not log_found:
        print("❌ No supported log file found. Exiting.")

if __name__ == "__main__":
    main()


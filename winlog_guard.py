import subprocess
import re
import os
import time

# Simulated log file (use your own test log on Windows)
LOG_FILES = [
    "C:\\Users\\pushp\\OneDrive\\Desktop\\test_log.log"
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

def block_ip(ip):
    print(f"[!] Simulated block of IP: {ip}")
    # Uncomment the next line only if you implement Windows firewall block
    # os.system(f"netsh advfirewall firewall add rule name=\"BlockIP\" dir=in action=block remoteip={ip}")

def analyze_log_entry(log_input):
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
    try:
        result = subprocess.run(
            ['ollama', 'run', 'shikigami'],
            input=prompt.encode(),
            capture_output=True,
            timeout=10
        )
        return result.stdout.decode()
    except Exception as e:
        print(f"[!] Ollama Error: {e}")
        return "Suspicious: No\nWhy: Ollama unavailable\nBlock IP: No\nSeverity: Low"

def parse_response(response, log_input):
    should_block = "Suspicious: Yes" in response or "Block IP: Yes" in response
    blocked_ips = []

    if should_block:
        match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', log_input)
        if match:
            ip = match.group(1)
            block_ip(ip)
            blocked_ips.append(ip)

    with open("shikigami_logs.txt", "a") as f:
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
        print("❌ No supported log file found. Waiting...")
    while True:
        for log_file in LOG_FILES:
            if os.path.exists(log_file):
                print(f"📡 Log appeared: {log_file}")
                main()
                return
        time.sleep(30)

if __name__ == "__main__":
    main()

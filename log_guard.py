import subprocess
import re
import os
from datetime import datetime

log_input = input("Enter log message to analyze: ")

# Prompt to the AI
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

# Run CyberGuard AI model
result = subprocess.run(
    ['ollama', 'run', 'cyberguard'],  # use 'llama2' if no custom model
    input=prompt.encode(),
    capture_output=True
)

# Decode response from model
response = result.stdout.decode()

# Print AI response
print("\nAI Says:\n")
print(response)

# === ✅ Step 4: Save log + AI response with timestamp ===
with open("cyberguard_logs.txt", "a") as f:
    f.write(f"{datetime.now()} - LOG: {log_input}\nRESPONSE:\n{response}\n{'-'*50}\n")

# === 🔒 Optional: Block IP if flagged ===
if "Suspicious: Yes" in response or "Block IP: Yes" in response:
    match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', log_input)
    if match:
        ip = match.group(1)
        print(f"[!] Blocking IP: {ip}")
        os.system(f'sudo iptables -A INPUT -s {ip} -j DROP')


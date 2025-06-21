import win32evtlog
import subprocess
import time

LOG_NAME = 'Security'  # Changed to 'Security' to catch event 4625
EVENT_IDS_OF_INTEREST = [4625, 4672, 4688, 4104]
last_record_number = 0  # Track last seen record number

def analyze_log_entry(log_entry):
    prompt = f"""
You are a cybersecurity AI assistant.

Analyze the following Windows event log in 30:

{log_entry}

Answer in this format in 30 seconds:
Suspicious (Yes/No):
Why:
Should Block IP (Yes/No):
Severity (Low/Medium/High/Critical):
"""
    try:
        result = subprocess.run(
            ['ollama', 'run', 'llama2:7B'],
            input=prompt.encode(),
            capture_output=True,
            timeout=360
        )
        return result.stdout.decode().strip()
    except Exception as e:
        print(f"[!] Error contacting Ollama: {e}")
        return "Suspicious: No\nWhy: AI unavailable\nBlock IP: No\nSeverity: Low"

def fetch_and_analyze():
    global last_record_number
    server = 'localhost'
    log_handle = win32evtlog.OpenEventLog(server, LOG_NAME)

    total = win32evtlog.GetNumberOfEventLogRecords(log_handle)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = win32evtlog.ReadEventLog(log_handle, flags, 0)

    for event in events:
        if event.RecordNumber <= last_record_number:
            break  # Already processed

        if event.EventID in EVENT_IDS_OF_INTEREST:
            log_data = f"EventID: {event.EventID}\nTime: {event.TimeGenerated}\nSource: {event.SourceName}\nMessage: {event.StringInserts}"
            print(f"\n🧠 Sending log to AI...\n{log_data}")
            response = analyze_log_entry(log_data)
            print("\nAI processing...\n", response)

        last_record_number = max(last_record_number, event.RecordNumber)

if __name__ == "__main__":
    print("[+] Starting Shikigami AI WinLog Guard...")
    while True:
        try:
            fetch_and_analyze()
            print(f"[+] Waiting for next scan... ({time.strftime('%H:%M:%S')})")
        except Exception as e:
            print(f"[!] Runtime error: {e}")
        time.sleep(30)

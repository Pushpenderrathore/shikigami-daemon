import win32evtlog
import time
import requests

LOG_NAME = 'Security'
EVENT_IDS_OF_INTEREST = [4625, 4672, 4688, 4104]
last_record_number = 0

def analyze_log_entry(log_entry):
    prompt = f"""
You are a cybersecurity log analyst.

Your job is to analyze Windows event logs and respond strictly in the format provided below.

LOG:
{log_entry}

Respond strictly in this format in 30 seconds:
Suspicious (Yes/No):
Why:
Should Block IP (Yes/No):
Severity (Low/Medium/High/Critical):
"""

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "mistral:7B",
                "prompt": prompt,
                "stream": False
            },
            timeout=300
        )
        result = response.json().get("response", "").strip()
        return result if result else "Suspicious: No\nWhy: AI returned nothing\nBlock IP: No\nSeverity: Low"
    except Exception as e:
        print(f"[!] Error contacting Ollama API: {e}")
        return "Suspicious: No\nWhy: AI unavailable\nShould Block IP: No\nSeverity: Low"

def fetch_and_analyze():
    global last_record_number
    server = 'localhost'
    log_handle = win32evtlog.OpenEventLog(server, LOG_NAME)

    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = win32evtlog.ReadEventLog(log_handle, flags, 0)

    if not events:
        return

    for event in events:
        if event.RecordNumber <= last_record_number:
            continue  # skip already seen

        print(f"[•] Checked EventID: {event.EventID} Record: {event.RecordNumber}")

        if event.EventID in EVENT_IDS_OF_INTEREST:
            log_data = f"EventID: {event.EventID}\nTime: {event.TimeGenerated}\nSource: {event.SourceName}\nMessage: {event.StringInserts}"
            print(f"\n🧠 Sending log to AI...\n{log_data}")
            response = analyze_log_entry(log_data)
            print("\nAI processing...\n", response)

        last_record_number = event.RecordNumber  # update after each

if __name__ == "__main__":
    print("[+] Starting Shikigami AI WinLog Guard...")
    while True:
        try:
            fetch_and_analyze()
            print(f"[+] Waiting for next scan... ({time.strftime('%H:%M:%S')})")
        except Exception as e:
            print(f"[!] Runtime error: {e}")
        time.sleep(5)

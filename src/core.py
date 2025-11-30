import os
import time
import requests
import matplotlib.pyplot as plt
import json
import hashlib
import math
import string
from datetime import datetime


def read_file_content(filepath):
    """
    Safely read a text file and return its content or None if:
    - file does not exist
    - file is empty
    """
    if not os.path.exists(filepath):
        return None

    # Open the file and read its contents
    with open(filepath, "r", encoding="utf-8") as file:
        content = file.read().strip()

        # If the file is empty after stripping whitespace, treat as None
        if not content:
            return None

        return content


# ==========================
# LOGGING HELPERS
# ==========================

LOG_DIR = "evidence/logs"
LOG_FILE = os.path.join(LOG_DIR, "security.log")


def log_event(module: str, message: str, level: str = "INFO") -> None:
    """
    Append a single log entry to evidence/logs/security.log.

    Format:
    [YYYY-MM-DD HH:MM:SS] [MODULE] [LEVEL] message
    """
    os.makedirs(LOG_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] [{module}] [{level}] {message}\n"

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)


# ==========================
# YAHYA'S MODULES
# ==========================

def password_assessment(password: str, simulate: bool = False):
    """
    Check password strength, entropy, SHA-256 hash, and whether it matches
    a small list of known weak passwords.

    If simulate=True, run the assessment on a set of common weak passwords
    and return a dict mapping password -> assessment result.
    """
    if simulate:
        test_passwords = ["admin123", "password", "12345678", "qwerty"]
        return {p: password_assessment(p, False) for p in test_passwords}

    # 1) Length
    length = len(password)

    # 2) Character categories
    categories = {
        "upper": any(c.isupper() for c in password),
        "lower": any(c.islower() for c in password),
        "digits": any(c.isdigit() for c in password),
        "special": any(c in string.punctuation for c in password),
    }

    # 3) Entropy estimation based on which character sets are used
    charset_size = (
        (26 if categories["upper"] else 0) +
        (26 if categories["lower"] else 0) +
        (10 if categories["digits"] else 0) +
        (32 if categories["special"] else 0)
    )
    entropy = round(length * math.log2(charset_size), 2) if charset_size > 0 else 0

    # 4) Hashing with SHA-256
    hashed = hashlib.sha256(password.encode()).hexdigest()

    # 5) Compare with known weak hashes
    weak_hashes = {
        hashlib.sha256("123456".encode()).hexdigest(),
        hashlib.sha256("password".encode()).hexdigest(),
        hashlib.sha256("admin123".encode()).hexdigest(),
    }
    weak = hashed in weak_hashes

    return {
        "password": password,
        "length": length,
        "categories": categories,
        "entropy_bits": entropy,
        "sha256": hashed,
        "is_weak": weak,
    }


def run_stress_test(url: str, total_requests: int = 200, throttle_every: int = 50, sleep_time: int = 1):
    """
    Simple HTTP stress test:
    - Sends multiple GET requests to the given URL
    - Measures latency for each
    - Saves:
      * latency graph to evidence/stress/latency_graph.png
      * raw data to evidence/stress/latency_data.json
    """
    latencies = []

    for i in range(total_requests):
        start = time.time()
        try:
            requests.get(url)
            latency = round((time.time() - start) * 1000, 2)  # in ms
        except Exception:
            latency = None

        latencies.append(latency)

        if (i + 1) % throttle_every == 0:
            time.sleep(sleep_time)

    stress_dir = "evidence/stress"
    os.makedirs(stress_dir, exist_ok=True)

    graph_path = os.path.join(stress_dir, "latency_graph.png")
    plt.figure()
    plt.plot(latencies)
    plt.title("Stress Test Latency")
    plt.xlabel("Request #")
    plt.ylabel("Latency (ms)")
    plt.savefig(graph_path)
    plt.close()

    json_path = os.path.join(stress_dir, "latency_data.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(latencies, f)

    return {
        "status": "completed",
        "total_requests": total_requests,
        "graph": graph_path,
        "json": json_path,
    }


def run_packet_capture(count: int = 50, output: str = "evidence/pcap/capture.pcap"):
    """
    Capture 'count' packets using scapy (if installed) and save:
    - raw packets to a .pcap file
    - a JSON summary to evidence/pcap/capture_summary.json

    If scapy is not installed, returns an error status and creates
    an empty summary file.
    """
    pcap_dir = "evidence/pcap"
    os.makedirs(pcap_dir, exist_ok=True)

    try:
        # Import scapy dynamically so the file can still be imported
        # even if scapy is not installed in the environment.
        import importlib
        scapy_all = importlib.import_module("scapy.all")
        sniff = getattr(scapy_all, "sniff")
        wrpcap = getattr(scapy_all, "wrpcap")
    except Exception:
        json_path = os.path.join(pcap_dir, "capture_summary.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump([], f)
        return {
            "status": "error",
            "message": "scapy is not installed; install it with 'pip install scapy' to enable packet capture.",
            "pcap_file": None,
            "summary_file": json_path,
            "packet_count": 0,
        }

    packets = sniff(count=count)
    wrpcap(output, packets)

    summary = []
    for pkt in packets:
        entry = {
            "src": getattr(pkt[0], "src", None),
            "dst": getattr(pkt[0], "dst", None),
            "proto": getattr(pkt[0], "name", None),
        }
        summary.append(entry)

    json_path = os.path.join(pcap_dir, "capture_summary.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f)

    return {
        "status": "ok",
        "pcap_file": output,
        "summary_file": json_path,
        "packet_count": len(packets),
    }

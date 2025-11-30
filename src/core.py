import os
import time
import requests
import matplotlib.pyplot as plt
import json
import os
# scapy import moved into run_packet_capture to avoid unresolved import in editors/missing environments
import hashlib
import math
import string

def read_file_content(filepath):
    #cheking if the file exists
    if not os.path.exists(filepath):
        return None 
    
    #opening the file and reading its contents
    with open (filepath, "r", encoding="utf-8") as file:
        content = file.read().strip()

        #if the file is incase empty
        if not content:
            return None
        
        #if the file is not empty, return the content inside of it
        return content


# ==========================
# YAHYA's MODULES
# ==========================


def password_assessment(password: str, simulate=False):
    """Check password strength, entropy, hash, and weak hash comparison."""
    
    if simulate:
        test_passwords = ["admin123", "password", "12345678", "qwerty"]
        return {p: password_assessment(p, False) for p in test_passwords}
    
    # 1. Length
    length = len(password)

    # 2. Character categories
    categories = {
        "upper": any(c.isupper() for c in password),
        "lower": any(c.islower() for c in password),
        "digits": any(c.isdigit() for c in password),
        "special": any(c in string.punctuation for c in password),
    }

    # 3. Entropy estimation
    charset_size = (
        (26 if categories["upper"] else 0) +
        (26 if categories["lower"] else 0) +
        (10 if categories["digits"] else 0) +
        (32 if categories["special"] else 0)
    )
    entropy = round(length * math.log2(charset_size), 2) if charset_size > 0 else 0

    # 4. Hashing
    hashed = hashlib.sha256(password.encode()).hexdigest()

    # 5. Compare with known weak hashes
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

def run_stress_test(url, total_requests=200, throttle_every=50, sleep_time=1):
    latencies = []

    for i in range(total_requests):
        start = time.time()
        try:
            requests.get(url)
            latency = round((time.time() - start) * 1000, 2)
        except:
            latency = None

        latencies.append(latency)

        if (i+1) % throttle_every == 0:
            time.sleep(sleep_time)

    # Save graph
    os.makedirs("evidence/stress", exist_ok=True)
    graph_path = "evidence/stress/latency_graph.png"

    plt.figure()
    plt.plot(latencies)
    plt.title("Stress Test Latency")
    plt.xlabel("Request #")
    plt.ylabel("Latency (ms)")
    plt.savefig(graph_path)
    plt.close()

    # Save JSON
    json_path = "evidence/stress/latency_data.json"
    with open(json_path, "w") as f:
        json.dump(latencies, f)

    return {
        "status": "completed",
        "total_requests": total_requests,
        "graph": graph_path,
        "json": json_path
    }


def run_packet_capture(count=50, output="evidence/pcap/capture.pcap"):
    os.makedirs("evidence/pcap", exist_ok=True)

    try:
        # importlib avoids a top-level "from scapy.all import ..." which some editors/linters cannot resolve
        import importlib
        scapy_all = importlib.import_module("scapy.all")
        sniff = getattr(scapy_all, "sniff")
        wrpcap = getattr(scapy_all, "wrpcap")
    except Exception:
        # Scapy is not available in this environment; return an informative error and create an empty summary.
        json_path = "evidence/pcap/capture_summary.json"
        with open(json_path, "w") as f:
            json.dump([], f)
        return {
            "status": "error",
            "message": "scapy is not installed; install it with 'pip install scapy' to enable packet capture.",
            "pcap_file": None,
            "summary_file": json_path,
            "packet_count": 0
        }

    packets = sniff(count=count)
    wrpcap(output, packets)

    summary = []

    for pkt in packets:
        entry = {
            "src": pkt[0].src if hasattr(pkt[0], "src") else None,
            "dst": pkt[0].dst if hasattr(pkt[0], "dst") else None,
            "proto": pkt[0].name
        }
        summary.append(entry)

    # save JSON
    json_path = "evidence/pcap/capture_summary.json"
    with open(json_path, "w") as f:
        json.dump(summary, f)

    return {
        "pcap_file": output,
        "summary_file": json_path,
        "packet_count": len(packets)
    }

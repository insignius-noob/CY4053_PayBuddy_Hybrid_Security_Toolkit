import os
import time
import socket
import json
import math
import string
import hashlib
import requests
import matplotlib.pyplot as plt
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor


# ==========================
# CORE HELPERS (MUTAAL)
# ==========================

def read_file_content(filepath: str):
    """
    Safely read a text file and return its content or None if:
    - file does not exist
    - file is empty (after stripping whitespace)
    """
    if not os.path.exists(filepath):
        return None

    with open(filepath, "r", encoding="utf-8") as file:
        content = file.read().strip()
        if not content:
            return None
        return content


# ==========================
# LOGGING HELPERS (MUTAAL)
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
# YAHYA'S MODULES: PASSWORD
# ==========================

def password_assessment(password: str, simulate: bool = False):
    """
    Check password strength, entropy, SHA-256 hash,
    and mark is_weak = True if:
      - It matches known weak hashes
      - OR it is missing any character category
    """

    if simulate:
        test_passwords = ["admin123", "password", "12345678", "qwerty"]
        return {p: password_assessment(p, False) for p in test_passwords}

    length = len(password)

    # Character categories
    categories = {
        "upper": any(c.isupper() for c in password),
        "lower": any(c.islower() for c in password),
        "digits": any(c.isdigit() for c in password),
        "special": any(c in string.punctuation for c in password),
    }

    # Entropy calculation
    charset_size = (
        (26 if categories["upper"] else 0) +
        (26 if categories["lower"] else 0) +
        (10 if categories["digits"] else 0) +
        (32 if categories["special"] else 0)
    )
    entropy = round(length * math.log2(charset_size), 2) if charset_size > 0 else 0

    # Hashing
    hashed = hashlib.sha256(password.encode()).hexdigest()

    # Known weak password hashes
    weak_hashes = {
        hashlib.sha256("123456".encode()).hexdigest(),
        hashlib.sha256("password".encode()).hexdigest(),
        hashlib.sha256("admin123".encode()).hexdigest(),
    }

    # Weak rules:
    # If ANY category is missing → weak
    missing_category = not all(categories.values())

    weak = (hashed in weak_hashes) or missing_category

    return {
        "password": password,
        "length": length,
        "categories": categories,
        "entropy_bits": entropy,
        "sha256": hashed,
        "is_weak": weak,
    }


# ==========================
# YAHYA'S MODULES: STRESS TEST
# ==========================

def run_stress_test(
    url: str,
    total_requests: int = 200,
    throttle_every: int = 50,
    sleep_time: int = 1
):
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


# ==========================
# YAHYA'S MODULES: PACKET CAPTURE
# ==========================

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


# ==========================
# UMER'S MODULES: PORT SCAN
# ==========================

SCAN_DIR = "evidence/scans"


def scan_single_port(target: str, port: int, timeout: float = 1.0) -> dict:
    """
    Try to connect to a single TCP port on the target.
    If open, optionally grab a simple banner (HTTP HEAD request).
    """
    result = {"port": port, "open": False, "banner": None}

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((target, port)) == 0:
                result["open"] = True
                try:
                    # Try to get a simple HTTP banner
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    data = s.recv(1024)
                    if data:
                        try:
                            result["banner"] = data.decode(errors="ignore").strip()
                        except Exception:
                            result["banner"] = repr(data)
                except Exception:
                    pass
    except Exception:
        pass

    return result


def port_scan(
    target: str,
    start_port: int = 1,
    end_port: int = 1024,
    max_workers: int = 50,
    output_prefix: str | None = None
) -> dict:
    """
    Scan a range of TCP ports on the target host using threads.
    Saves JSON + HTML evidence if output_prefix is provided.
    """
    start_time = time.time()
    ports = range(start_port, end_port + 1)
    results: list[dict] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_single_port, target, p): p
            for p in ports
        }
        for future in future_to_port:
            res = future.result()
            results.append(res)

    duration = round(time.time() - start_time, 2)
    summary = {
        "target": target,
        "start_port": start_port,
        "end_port": end_port,
        "total_ports": len(ports),
        "scan_duration_sec": duration,
        "results": results,
    }

    json_path = None
    html_path = None

    if output_prefix:
        os.makedirs(SCAN_DIR, exist_ok=True)
        json_path = os.path.join(SCAN_DIR, f"{output_prefix}.json")
        html_path = os.path.join(SCAN_DIR, f"{output_prefix}.html")

        # Save JSON summary
        with open(json_path, "w", encoding="utf-8") as jf:
            json.dump(summary, jf, indent=2)

        # Save basic HTML report
        with open(html_path, "w", encoding="utf-8") as hf:
            hf.write("<html><head><title>Port Scan Report</title></head><body>\n")
            hf.write(f"<h1>Port Scan Report for {target}</h1>\n")
            hf.write(f"<p>Ports {start_port}–{end_port}, "
                     f"duration {duration} seconds.</p>\n")
            hf.write("<table border='1' cellpadding='4' cellspacing='0'>\n")
            hf.write("<tr><th>Port</th><th>Status</th><th>Banner</th></tr>\n")
            for r in results:
                status = "OPEN" if r["open"] else "closed"
                banner = (r["banner"] or "").replace("\n", " ")[:200]
                hf.write(f"<tr><td>{r['port']}</td><td>{status}</td><td>{banner}</td></tr>\n")
            hf.write("</table></body></html>\n")

    summary["json_path"] = json_path
    summary["html_path"] = html_path
    return summary


# ==========================
# UMER'S MODULES: FOOTPRINT
# ==========================

FOOTPRINT_DIR = "evidence/footprint"

DEFAULT_PATHS = [
    "admin", "login", "uploads", "images",
    "js", "css", "dashboard", "api", "backup"
]

DEFAULT_SUBS = ["www", "api", "dev", "test", "admin"]


def _safe_request(url: str, timeout: float = 3.0):
    """
    Helper to send a GET request and not crash on errors.
    Returns (status_code, final_url, content_length) or (None, None, None).
    """
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        status = resp.status_code
        final_url = resp.url
        length = len(resp.content)
        return status, final_url, length
    except Exception:
        return None, None, None


def enumerate_directories(domain: str, prefix: str = "scan1"):
    """
    Enumerate common directories on a target website.

    - domain: e.g. "testphp.vulnweb.com" or "https://juice-shop.herokuapp.com"
    - prefix: used to name the evidence file, e.g. "scan1" -> scan1_dirs.json

    What it does:
    1) Normalises the domain into a full URL (adds http:// if missing)
    2) Tries a small wordlist of common paths:
       /admin, /login, /uploads, /images, /js, /css, /dashboard
    3) Sends HTTP GET for each path and records:
       - full URL
       - status code (200, 403, 404, etc.)
       - response body length
    4) Saves everything into evidence/footprint/<prefix>_dirs.json
    5) Returns a dict with summary + the path of the JSON file.
    """

    # Make sure evidence directory exists
    os.makedirs(FOOTPRINT_DIR, exist_ok=True)

    # Normalise domain into a base URL
    domain = domain.strip()
    if not domain:
        # No domain, nothing to do
        return {
            "target": None,
            "checked": 0,
            "paths": [],
            "output_file": None,
        }

    if not domain.startswith("http://") and not domain.startswith("https://"):
        base_url = "http://" + domain
    else:
        base_url = domain

    # Wordlist used for enumeration
    wordlist = ["admin", "login", "uploads", "images", "js", "css", "dashboard"]

    results = []

    for p in wordlist:
        # Build URL like http://target/admin
        url = base_url.rstrip("/") + "/" + p
        try:
            resp = requests.get(url, timeout=5)
            status = resp.status_code
            length = len(resp.text)
        except Exception:
            status = None
            length = None

        results.append(
            {
                "path": "/" + p,   # for display
                "url": url,
                "status": status,
                "length": length,
            }
        )

    # Save JSON evidence file
    out_path = os.path.join(FOOTPRINT_DIR, f"{prefix}_dirs.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "target": domain,
                "checked": len(wordlist),
                "paths": results,
            },
            f,
            indent=2,
        )

    # Return a summary for the UI
    return {
        "target": domain,
        "checked": len(wordlist),
        "paths": results,
        "output_file": out_path,
    }



def enumerate_subdomains(domain: str, prefix: str = "scan1"):
    """
    Enumerate common subdomains for the given domain.

    - domain: e.g. "owasp.org"
    - prefix: used to name the evidence file, e.g. "scan1" -> scan1_subs.json

    What it does:
    1) Builds hostnames like:
       www.<domain>, admin.<domain>, test.<domain>, dev.<domain>, mail.<domain>
    2) Tries to resolve each with DNS (socket.gethostbyname)
    3) Marks each as reachable or not
    4) Saves everything into evidence/footprint/<prefix>_subs.json
    5) Returns a dict with summary + the path of the JSON file.
    """

    os.makedirs(FOOTPRINT_DIR, exist_ok=True)

    domain = domain.strip()
    if not domain:
        return {
            "target": None,
            "checked": 0,
            "subdomains": [],
            "output_file": None,
        }

    sub_list = ["www", "admin", "test", "dev", "mail"]
    results = []

    for sub in sub_list:
        host = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            reachable = True
        except Exception:
            ip = None
            reachable = False

        results.append(
            {
                "host": host,
                "ip": ip,
                "reachable": reachable,
            }
        )

    out_path = os.path.join(FOOTPRINT_DIR, f"{prefix}_subs.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "target": domain,
                "checked": len(sub_list),
                "subdomains": results,
            },
            f,
            indent=2,
        )

    return {
        "target": domain,
        "checked": len(sub_list),
        "subdomains": results,
        "output_file": out_path,
    }



def save_footprint_json(
    prefix: str,
    dirs_result: dict | None = None,
    subs_result: dict | None = None
) -> str:
    """
    Save directory and subdomain enumeration results as JSON
    into evidence/footprint/ with the given prefix.
    Returns the directory path used.
    """
    os.makedirs(FOOTPRINT_DIR, exist_ok=True)

    if dirs_result is not None:
        dirs_path = os.path.join(FOOTPRINT_DIR, f"{prefix}_dirs.json")
        with open(dirs_path, "w", encoding="utf-8") as f:
            json.dump(dirs_result, f, indent=2)

    if subs_result is not None:
        subs_path = os.path.join(FOOTPRINT_DIR, f"{prefix}_subs.json")
        with open(subs_path, "w", encoding="utf-8") as f:
            json.dump(subs_result, f, indent=2)

    return FOOTPRINT_DIR


# ==========================
# REPORT GENERATION (MUTAAL)
# ==========================

def _latest_file_in_dir(directory: str, extensions: tuple) -> str | None:
    """
    Helper function:
    - Look into 'directory'
    - Filter files that end with any of the given 'extensions'
    - Return the full path of the most recently modified one
    - If nothing found, return None
    """
    if not os.path.isdir(directory):
        return None

    files = [
        f for f in os.listdir(directory)
        if f.lower().endswith(extensions)
    ]
    if not files:
        return None

    # Pick the newest file based on modification time
    files_full = [os.path.join(directory, f) for f in files]
    latest = max(files_full, key=os.path.getmtime)
    return latest


def generate_report(report_path: str = "evidence/report_PHST.txt") -> str:
    """
    Auto-generate a simple text report that summarizes:
    - Identity & consent
    - Log file path
    - Latest scan / footprint / stress / pcap evidence

    Returns the full path of the report file.
    """
    os.makedirs("evidence", exist_ok=True)

    # 1) Identity & consent
    identity = read_file_content("../identity.txt")
    consent = read_file_content("../consent.txt")

    # 2) Logging info
    log_file = LOG_FILE if os.path.exists(LOG_FILE) else None

    # 3) Latest port scan evidence
    latest_scan_json = _latest_file_in_dir("evidence/scans", (".json",))
    latest_scan_html = _latest_file_in_dir("evidence/scans", (".html",))

    # 4) Latest footprint evidence
    latest_footprint_json = _latest_file_in_dir("evidence/footprint", (".json",))

    # 5) Stress test evidence (latency data)
    stress_json = _latest_file_in_dir("evidence/stress", (".json",))
    stress_summary = None
    if stress_json is not None:
        try:
            with open(stress_json, "r", encoding="utf-8") as f:
                latencies = json.load(f)
            if isinstance(latencies, list) and latencies:
                avg_latency = sum(v for v in latencies if v is not None) / max(
                    1, len([v for v in latencies if v is not None])
                )
                stress_summary = {
                    "count": len(latencies),
                    "avg_ms": round(avg_latency, 2),
                }
        except Exception:
            stress_summary = None

    # 6) Packet capture summary
    pcap_summary_json = _latest_file_in_dir("evidence/pcap", (".json",))
    pcap_summary_info = None
    if pcap_summary_json is not None:
        try:
            with open(pcap_summary_json, "r", encoding="utf-8") as f:
                pcap_data = json.load(f)
            if isinstance(pcap_data, list):
                pcap_summary_info = {
                    "packet_count": len(pcap_data)
                }
            else:
                pcap_summary_info = {"note": "Non-list JSON, see file for details."}
        except Exception:
            pcap_summary_info = None

    # 7) Write the report
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []
    lines.append("PayBuddy Hybrid Security Toolkit – Summary Report")
    lines.append(f"Generated at: {now_str}")
    lines.append("")
    lines.append("=== Identity & Consent ===")
    if identity:
        lines.append("Identity: PRESENT")
    else:
        lines.append("Identity: MISSING or EMPTY")
    if consent:
        lines.append("Consent: PRESENT")
    else:
        lines.append("Consent: MISSING or EMPTY")
    lines.append("")

    lines.append("=== Logging ===")
    if log_file:
        lines.append(f"Security log file: {log_file}")
    else:
        lines.append("No security log file found.")
    lines.append("")

    lines.append("=== Port Scan Evidence ===")
    if latest_scan_json or latest_scan_html:
        if latest_scan_json:
            lines.append(f"Latest scan JSON: {latest_scan_json}")
        if latest_scan_html:
            lines.append(f"Latest scan HTML: {latest_scan_html}")
    else:
        lines.append("No scan evidence files found in evidence/scans.")
    lines.append("")

    lines.append("=== Footprint Evidence ===")
    if latest_footprint_json:
        lines.append(f"Latest footprint JSON: {latest_footprint_json}")
    else:
        lines.append("No footprint evidence files found in evidence/footprint.")
    lines.append("")

    lines.append("=== HTTP Stress Test Evidence ===")
    if stress_json and stress_summary:
        lines.append(f"Latency JSON: {stress_json}")
        lines.append(
            f"Requests: {stress_summary['count']}, "
            f"Average latency: {stress_summary['avg_ms']} ms"
        )
    elif stress_json:
        lines.append(f"Latency JSON found (could not summarize): {stress_json}")
    else:
        lines.append("No stress test evidence found in evidence/stress.")
    lines.append("")

    lines.append("=== Packet Capture Evidence ===")
    if pcap_summary_json and pcap_summary_info:
        lines.append(f"PCAP summary JSON: {pcap_summary_json}")
        if "packet_count" in pcap_summary_info:
            lines.append(f"Packets captured (according to summary): {pcap_summary_info['packet_count']}")
        else:
            lines.append("See summary JSON for details.")
    elif pcap_summary_json:
        lines.append(f"PCAP summary JSON found (could not parse): {pcap_summary_json}")
    else:
        lines.append("No packet capture evidence found in evidence/pcap.")
    lines.append("")

    # Finally, write to file
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    # Also log this event
    log_event("report", f"Report generated at {report_path}", "INFO")

    return report_path


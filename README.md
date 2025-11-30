PayBuddy Hybrid Security Toolkit (PHST)
Offensive + Defensive Security Automation Toolkit (Python)

This toolkit allows ethical security testers to perform lightweight scanning, enumeration, stress testing, packet capturing, password auditing, and automated reporting — all bundled into a single Python module.

📦 1. Installation
Clone the project
git clone https://github.com/insignius-noob/CY4053_PayBuddy_Hybrid_Security_Toolkit.git

Install requirements
pip install -r requirements.txt

Ensure directory structure

The toolkit automatically creates required folders inside:

evidence/
 ├── logs/
 ├── scans/
 ├── stress/
 ├── pcap/
 └── footprint/


Place these files one folder above your script:

../identity.txt
../consent.txt


These are required to confirm that testing is authorized.

📚 2. Features Overview

This toolkit contains several modules, each responsible for an area of ethical penetration testing.

🔐 Password Strength Assessment

password_assessment(password) performs:

Length analysis

Character category checks (upper/lower/digits/special)

Entropy calculation (bits)

SHA-256 hashing

Weak password detection (via known weak hashes)

Additional Rule:
If ANY character category (upper/lower/digit/special) is missing → is_weak = True

Example:

result = password_assessment("Hello123!")
print(result)

⚡ Stress Testing (HTTP GET Flood – Safe)

run_stress_test(url, total_requests=200):

Sends repeated GET requests

Measures latency for each

Automatically throttles after every 50 requests

Saves:

latency_graph.png

latency_data.json

Example:

run_stress_test(
    "https://juice-shop.herokuapp.com",
    total_requests=100,
    throttle_every=20
)

📡 Packet Capture (Scapy Sniffer)

run_packet_capture(count=50):

Captures raw packets using scapy

Saves:

.pcap file

JSON summary (src, dst, proto)

Requires admin privileges on most systems

Example:

run_packet_capture(count=30)

🛠 Port Scanning (TCP SYN-like using sockets)

port_scan(target, 1, 1024):

Multi-threaded (ThreadPoolExecutor)

Attempts TCP connections to ports

Extracts simple HTTP banners

Saves:

JSON report

HTML report

Example:

port_scan("example.com", 1, 500, output_prefix="example_scan")

🌐 Footprinting (Directory + Subdomain Enumeration)
Directory Enumeration

Checks common paths such as /admin, /login, /uploads.

enumerate_directories("example.com")

Subdomain Enumeration

Checks subdomains such as www., api., dev., test., admin.

enumerate_subdomains("example.com")


All results are savable via:

save_footprint_json("example", dirs_result, subs_result)

📝 Automatic Report Generation
generate_report()


Creates a combined text report summarizing:

Identity & consent

Logs

Latest scan results

Latest footprint results

Stress test data summary

Packet capture summary

Output file:

evidence/report_PHST.txt

▶ Running the Toolkit (Example Workflow)
from core import *

# Verify identity & consent manually
print("Starting security toolkit...")

# Run modules
password_assessment("P@ssw0rd!")
run_stress_test("https://juice-shop.herokuapp.com")
run_packet_capture(count=50)

scan = port_scan("example.com", 1, 1024, output_prefix="example_scan")

dirs = enumerate_directories("example.com")
subs = enumerate_subdomains("example.com")
save_footprint_json("example", dirs, subs)

generate_report()

⚠ Legal Disclaimer

This toolkit is only for academic and authorized penetration testing purposes.
You must have written permission (consent.txt + identity.txt) before scanning any system.

The authors are not responsible for misuse.

✔ Requirements

See requirements.txt.

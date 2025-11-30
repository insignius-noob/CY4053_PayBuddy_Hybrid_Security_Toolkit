from security import validate_identity, validate_consent
from core import (
    password_assessment,
    port_scan,
    run_stress_test,
    run_packet_capture,
    enumerate_directories,
    enumerate_subdomains,
    save_footprint_json,
)
from register import register_user


def show_menu():
    print("\n=== PAYBUDDY HYBRID SECURITY TOOLKIT ===")
    print("1. Password assessment")
    print("2. User registration")
    print("3. Port scan")
    print("4. Directory enumeration")
    print("5. Subdomain scan")
    print("6. HTTP stress test")
    print("7. Packet capture")
    print("0. Exit")


def main():
    # --- 1) Identity + Consent checks (startup requirement) ---
    print("=== PayBuddy Hybrid Security Toolkit ===")
    validate_identity()
    validate_consent()
    print("Startup security checks complete.\n")

    # --- 2) Main menu loop ---
    while True:
        show_menu()
        choice = input("Select an option: ").strip()

        # 1) Password assessment
        if choice == "1":
            print("\n--- Password Assessment ---")
            pwd = input("Enter a password to check: ").strip()
            result = password_assessment(pwd)

            print("\nRESULT")
            for key, value in result.items():
                print(f"{key}: {value}")

        # 2) User registration
        elif choice == "2":
            register_user()

        # 3) Port scan
        elif choice == "3":
            print("\n--- Port Scan ---")
            target = input("Enter target host (e.g. 127.0.0.1 or testphp.vulnweb.com): ").strip()
            try:
                start_port = int(input("Start port: ").strip())
                end_port = int(input("End port: ").strip())
            except ValueError:
                print("[ERROR] Ports must be numbers.")
                continue

            summary = run_port_scan(target, start_port, end_port)

            print("\nPort scan summary:")
            print("  Target:", summary.get("target"))
            print("  Range:", summary.get("start_port"), "-", summary.get("end_port"))
            print("  Duration (sec):", summary.get("duration"))
            print("  Open ports:", summary.get("open_ports"))
            print("  JSON report:", summary.get("json_report"))
            print("  HTML report:", summary.get("html_report"))

        # 4) Directory enumeration
        elif choice == "4":
            print("\n--- Directory Enumeration ---")
            # enumerate_directories expects just host, it builds http://host itself
            target = input("Enter target host (e.g. testphp.vulnweb.com): ").strip()
            dirs_result = enumerate_directories(target)

            # save evidence JSON
            prefix = f"dirs_{target.replace('.', '_')}"
            save_footprint_json(prefix, dirs_result, None)

            print("\nDirectory enumeration result:")
            print("  Target:", dirs_result.get("target"))
            print("  Paths checked:", dirs_result.get("checked"))
            print("  Valid responses found:", len(dirs_result.get("found", [])))
            print("  JSON files saved in: evidence/footprint")

        # 5) Subdomain scan
        elif choice == "5":
            print("\n--- Subdomain Scan ---")
            base_domain = input("Enter base domain (e.g. vulnweb.com or example.com): ").strip()
            subs_result = enumerate_subdomains(base_domain)

            # save evidence JSON
            prefix = f"subs_{base_domain.replace('.', '_')}"
            save_footprint_json(prefix, None, subs_result)

            print("\nSubdomain scan result:")
            print("  Base domain:", subs_result.get("base_domain"))
            print("  Subdomains checked:", subs_result.get("checked"))
            print("  JSON files saved in: evidence/footprint")

        # 6) HTTP stress test
        elif choice == "6":
            print("\n--- HTTP Stress Test ---")
            url = input("Enter URL to stress-test (e.g. https://testphp.vulnweb.com): ").strip()
            info = run_stress_test(url)

            print("\nStress test completed:")
            print("  Status:", info.get("status"))
            print("  Total requests:", info.get("total_requests"))
            print("  Latency graph:", info.get("graph"))
            print("  JSON data:", info.get("json"))

        # 7) Packet capture
        elif choice == "7":
            print("\n--- Packet Capture ---")
            count_str = input("How many packets to capture? (e.g. 50): ").strip()
            try:
                count = int(count_str) if count_str else 50
            except ValueError:
                print("[ERROR] Packet count must be a number.")
                continue

            info = run_packet_capture(count=count)

            print("\nPacket capture result:")
            print("  Status:", info.get("status"))
            if "message" in info:
                print("  Message:", info.get("message"))
            print("  PCAP file:", info.get("pcap_file"))
            print("  Summary file:", info.get("summary_file"))
            print("  Packet count:", info.get("packet_count"))

        # Exit
        elif choice == "0":
            print("\nExiting... Goodbye!")
            break

        else:
            print("\nInvalid option. Try again.")


if __name__ == "__main__":
    main()

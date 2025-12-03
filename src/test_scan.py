from core import port_scan

def main():
    print("=== TEST: PORT SCAN MODULE (UMER) ===")

    
    target = "127.0.0.1"  # localhost for testing
    start_port = 70
    end_port = 90

    print(f"Scanning {target} from port {start_port} to {end_port} ...")
    result = port_scan(
        target=target,
        start_port=start_port,
        end_port=end_port,
        max_workers=50,
        output_prefix="test_scan_umer"
    )

    print("Scan summary:")
    print("  Target:", result["target"])
    print("  Ports:", result["start_port"], "to", result["end_port"])
    print("  Duration (sec):", result["scan_duration_sec"])
    print("  JSON report:", result["json_path"])
    print("  HTML report:", result["html_path"])

    open_ports = [r["port"] for r in result["results"] if r["open"]]
    print("  Open ports found:", open_ports)


if __name__ == "__main__":
    main()

# test_yahya.py
"""
Developer test file for Yahya's modules:
- password_assessment
- run_stress_test
- run_packet_capture

This is NOT the main application. It is only for testing his tools.
"""

from core import (
    password_assessment,
    run_stress_test,
    run_packet_capture,
)


def test_password_assessment():
    print("\n===== Testing Password Assessment (single password) =====")
    pwd = "Test123!"
    result = password_assessment(pwd)
    print("Input Password:", pwd)
    print("Result:")
    for key, value in result.items():
        print(f"  {key}: {value}")


def test_password_simulation():
    print("\n===== Testing Weak Password Simulation =====")
    simulation = password_assessment("", simulate=True)
    for pwd, info in simulation.items():
        print(f"\nPassword: {pwd}")
        for key, value in info.items():
            print(f"  {key}: {value}")


def test_stress_test():
    print("\n===== Testing Stress Test (HTTP) =====")
    # IMPORTANT:
    # Use ONLY an approved lab / practice URL here.
    # Replace this with the target you have written in consent.txt under Approved Targets.
    url = "https://example.com"  # TEMP placeholder; change later to approved target
    result = run_stress_test(url, total_requests=20, throttle_every=10, sleep_time=1)
    print("Stress test result:")
    for key, value in result.items():
        print(f"  {key}: {value}")


def test_packet_capture():
    print("\n===== Testing Packet Capture =====")
    # This will only work if scapy + WinPcap/Npcap are installed.
    result = run_packet_capture(count=10, output="evidence/pcap/test_capture.pcap")
    print("Packet capture result:")
    for key, value in result.items():
        print(f"  {key}: {value}")


def main():
    print("\n============================")
    print("   YAHYA'S MODULE TEST RUN  ")
    print("============================")

    # Always safe:
    test_password_assessment()
    test_password_simulation()

    # The next two can be commented/uncommented depending on environment:

    # 1) ONLY run this if you have internet and an approved lab URL configured
    # test_stress_test()

    # 2) ONLY run this if scapy + WinPcap/Npcap are installed
    # test_packet_capture()

    print("\n============================")
    print("      ALL TESTS COMPLETED   ")
    print("============================")


if __name__ == "__main__":
    main()

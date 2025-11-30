# test_yahya.py
from core import (
    password_assessment,
    run_stress_test,
    run_packet_capture
)

def test_password_assessment():
    print("\n===== Testing Password Assessment =====")
    pwd = "Test123!"
    result = password_assessment(pwd)
    print("Input Password:", pwd)
    print("Result:\n", result)

def test_password_simulation():
    print("\n===== Testing Weak Password Simulation =====")
    results = password_assessment("", simulate=True)
    print(results)

def test_stress_test():
    print("\n===== Testing Stress Test =====")
    url = "https://example.com"  # Change if needed
    result = run_stress_test(url, total_requests=10, throttle_every=5, sleep_time=1)
    print(result)

def test_packet_capture():
    print("\n===== Testing Packet Capture =====")
    result = run_packet_capture(count=5)
    print(result)

def main():
    print("\n============================")
    print(" YAHYA'S MODULE TEST START ")
    print("============================")

    test_password_assessment()
    test_password_simulation()
    test_stress_test()      # UNCOMMENT ONLY IF YOU HAVE INTERNET
    test_packet_capture()   # UNCOMMENT ONLY IF YOU HAVE WINPCAP/NPcap INSTALLED

    print("\n============================")
    print("  ALL TESTS COMPLETED")
    print("============================")

if __name__ == "__main__":
    main()

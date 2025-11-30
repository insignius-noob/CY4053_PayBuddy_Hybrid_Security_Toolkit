from core import read_file_content, log_event

IDENTITY_FILE = "identity.txt"
CONSENT_FILE = "consent.txt"


def validate_identity() -> str:
    """
    Read identity.txt and make sure it is not missing / empty.
    If it's okay, print [OK] and return the text.
    If it's bad, print [ERROR], log, and exit the program.
    """
    identity = read_file_content(IDENTITY_FILE)

    if identity is None:
        msg = "Identity missing or empty. Please fill identity.txt before using the toolkit."
        print(f"[ERROR] {msg}")
        log_event("identity", msg, "ERROR")
        raise SystemExit(1)

    print("[OK] Identity verified.")
    log_event("identity", "Identity verified successfully", "INFO")
    return identity


def validate_consent() -> str:
    """
    Same idea as validate_identity, but for consent.txt.
    """
    consent = read_file_content(CONSENT_FILE)

    if consent is None:
        msg = "Consent missing or empty. Please fill consent.txt before using the toolkit."
        print(f"[ERROR] {msg}")
        log_event("consent", msg, "ERROR")
        raise SystemExit(1)

    print("[OK] Consent verified.")
    log_event("consent", "Consent verified successfully", "INFO")
    return consent


def run_startup_checks() -> None:
    """
    Run at the beginning of the toolkit (from main.py).
    Makes sure identity and consent files are valid.
    """
    print("=== PayBuddy Hybrid Security Toolkit ===")
    print("Starting security checks...\n")

    identity = validate_identity()
    consent = validate_consent()

    print("\nAll security checks passed.")
    print("Welcome, identity file content:")
    print(identity)
    print("\n(Consent file has also been verified.)")

from core import read_file_content

def validate_identity(identity_path = "identity.txt"):
    identity = read_file_content(identity_path)

    if identity is None:
        print("Identity missing or empty. Please fill your name first.")
        exit(1)

    print(f"Okay, Identity Verified: {identity}")
    return identity



def validate_consent(consent_path="consent.txt"):

    consent = read_file_content(consent_path)

    if consent is None:
        print("[ERROR] Consent missing or empty. Please fill consent.txt before using the toolkit.")
        exit(1)

    print("[OK] Consent verified.")
    return consent
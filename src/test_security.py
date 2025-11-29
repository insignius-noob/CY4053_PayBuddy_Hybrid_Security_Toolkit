from security import validate_identity, validate_consent

def main():
    print("Testing identity and consent validation")
    identity = validate_identity()
    consent = validate_consent()

    print("All checks passed.")
    print("Identity from file:", identity)
    print("Consent from file:", consent)

if __name__ == "__main__":
    main()

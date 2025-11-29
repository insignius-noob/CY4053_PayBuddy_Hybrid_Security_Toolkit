from security import validate_identity, validate_consent

def main():
    print("=== PayBuddy Hybrid Security Toolkit ===")
    print("Starting security checks...\n")

    user_identity = validate_identity()
    user_consent = validate_consent()

    print("\nAll security checks passed.")
    print(f"Welcome, {user_identity}.")
    print("You can now safely use the toolkit features.")
    # Later: show menu / start UI / call other tools

if __name__ == "__main__":
    main()

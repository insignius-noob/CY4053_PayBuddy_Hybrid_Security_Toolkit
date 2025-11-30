import os
from core import password_assessment, log_event

USER_DB_DIR = "evidence"
USER_DB_FILE = os.path.join(USER_DB_DIR, "users.txt")


def ensure_user_db():
    """
    Make sure evidence/users.txt exists.
    If it doesn't, create it with a simple header line.
    """
    os.makedirs(USER_DB_DIR, exist_ok=True)

    if not os.path.exists(USER_DB_FILE):
        with open(USER_DB_FILE, "w", encoding="utf-8") as f:
            f.write("username,sha256_hash,entropy_bits\n")


def register_user():
    """
    CLI-based user registration:

    - asks for username
    - asks for password + confirm
    - checks password strength using password_assessment()
    - rejects weak / common passwords
    - stores username + hashed password in evidence/users.txt
    - logs all important events using log_event()
    """
    ensure_user_db()

    print("\n=== USER REGISTRATION ===")

    # 1) Ask for username
    username = input("Enter a username: ").strip()
    if not username:
        print("[ERROR] Username cannot be empty.")
        log_event("register", "Empty username entered", "ERROR")
        return

    # 2) Check if username already exists
    with open(USER_DB_FILE, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    for line in lines[1:]:  # skip header
        parts = line.split(",")
        if len(parts) >= 1 and parts[0] == username:
            print("[ERROR] This username already exists. Choose another.")
            log_event("register", f"Duplicate username: {username}", "WARNING")
            return

    # 3) Ask for password twice
    password = input("Enter a password: ").strip()
    confirm = input("Confirm password: ").strip()

    if password != confirm:
        print("[ERROR] Passwords do not match.")
        log_event("register", f"Password mismatch for username {username}", "ERROR")
        return

    # 4) Assess password strength using Yahya's function
    assessment = password_assessment(password)

    # Simple policy: at least 8 chars, not weak, entropy >= 40 bits
    if assessment["length"] < 8 or assessment["is_weak"] or assessment["entropy_bits"] < 40:
        print("\n[ERROR] Weak password. Please choose a stronger one.")
        print("Details:")
        for key, value in assessment.items():
            print(f"  {key}: {value}")
        log_event("register", f"Weak password attempt by {username}", "WARNING")
        return

    # 5) Save username + hashed password
    hashed = assessment["sha256"]
    with open(USER_DB_FILE, "a", encoding="utf-8") as f:
        f.write(f"{username},{hashed},{assessment['entropy_bits']}\n")

    print("\n[OK] User registered successfully!")
    log_event("register", f"User {username} registered successfully", "INFO")

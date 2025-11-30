from core import read_file_content, log_event

from core import read_file_content, log_event


def validate_identity(identity_path="identity.txt"):
    # Step 1: read the identity file using our helper
    identity = read_file_content(identity_path)

    # If file is missing or empty, stop
    if identity is None:
        print("[ERROR] Identity missing or empty. Please fill identity.txt before using the toolkit.")
        log_event("IDENTITY", "Identity missing or empty", level="ERROR")
        exit(1)

    # Step 2: enforce basic structure / content
    # Make a lowercase version so checks are case-insensitive
    lower_identity = identity.lower()

    missing_parts = []

    # Check that "team:" exists
    if "team:" not in lower_identity:
        missing_parts.append("Team name (line starting with 'Team:')")

    # Check that all 3 member names exist somewhere in the file
    if "mutaal" not in lower_identity:
        missing_parts.append("Member name: Mutaal")
    if "umer" not in lower_identity:
        missing_parts.append("Member name: Umer")
    if "yahya" not in lower_identity:
        missing_parts.append("Member name: Yahya")

    if missing_parts:
        # Join the missing parts into one string like: "Team name..., Member name: Umer, ..."
        details = "; ".join(missing_parts)
        print(f"[ERROR] Identity file is incomplete. Missing: {details}")
        log_event("IDENTITY", f"Identity file incomplete. Missing: {details}", level="ERROR")
        exit(1)

    # On reaching here, identity file exists, non-empty, and has basic required structure
    print("[OK] Identity verified.")
    log_event("IDENTITY", f"Identity verified from {identity_path}", level="INFO")
    return identity




def validate_consent(consent_path="consent.txt"):
    # Step 1: read consent file
    consent = read_file_content(consent_path)

    if consent is None:
        print("[ERROR] Consent missing or empty. Please fill consent.txt before using the toolkit.")
        log_event("CONSENT", "Consent missing or empty", level="ERROR")
        exit(1)

    # Step 2: look for "Approved Targets:" section
    lines = consent.splitlines()
    approved_targets = []
    in_targets_section = False

    for line in lines:
        stripped = line.strip()

        # Detect the start of the approved targets section
        if stripped.lower().startswith("approved targets"):
            in_targets_section = True
            # Don't treat this header line as a target itself, continue to next
            continue

        # Once we are in the targets section, collect non-empty lines as targets
        if in_targets_section:
            if stripped == "":
                # Blank line = end of targets list (we can stop reading further)
                break
            approved_targets.append(stripped)

    if not approved_targets:
        print("[ERROR] Consent file does not contain any approved targets under 'Approved Targets:'.")
        log_event("CONSENT", "Consent file missing approved targets", level="ERROR")
        exit(1)

    # Similarly on reaching here, consent file exists, non-empty, with at least one approved target
    print("[OK] Consent verified.")
    log_event("CONSENT", f"Consent verified from {consent_path} with {len(approved_targets)} approved target(s).", level="INFO")
    return consent

from core import enumerate_directories, enumerate_subdomains, save_footprint_json

def main():
    print("=== TEST: FOOTPRINT MODULE (UMER) ===")

    # Change these to your approved lab host/domain when demoing.
    target_host = "example.com"       # for directory enumeration
    base_domain = "example.com"       # for subdomain enumeration
    prefix = "test_footprint_umer"

    print(f"Enumerating directories on: {target_host}")
    dirs_result = enumerate_directories(
        target=target_host,
        scheme="https",
        rate_limit=0.2
    )
    print(f"  Checked {dirs_result['checked']} paths, found {len(dirs_result['found'])} valid responses.")

    print(f"\nEnumerating subdomains for: {base_domain}")
    subs_result = enumerate_subdomains(
        base_domain=base_domain,
        scheme="https",
        rate_limit=0.2
    )
    print(f"  Checked {subs_result['checked']} subdomains.")

    outdir = save_footprint_json(
        prefix=prefix,
        dirs_result=dirs_result,
        subs_result=subs_result
    )
    print("\nJSON footprint files saved in:", outdir)


if __name__ == "__main__":
    main()

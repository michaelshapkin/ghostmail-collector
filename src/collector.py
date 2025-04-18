import requests
import os
import json
import re
import functools # Ensure this is imported
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import dns.exception
from collections import Counter
from tqdm import tqdm

# List of sources for disposable email domains
SOURCES = [
    "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf",
    "https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json",
    "https://api.tremendous.com/prohibited_email_domains.txt",
    "https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains.txt",
    "https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains_strict.txt",
    "https://www.stopforumspam.com/downloads/toxic_domains_whole.txt",
    "https://gist.githubusercontent.com/adamloving/4401361/raw/e81212c3caecb54b87ced6392e0a0de2b6466287/temporary-email-address-domains",
    "https://raw.githubusercontent.com/unkn0w/disposable-email-domain-list/refs/heads/main/domains.txt",
    "https://raw.githubusercontent.com/GeroldSetz/emailondeck.com-domains/refs/heads/master/emailondeck.com_domains_from_bdea.cc.txt",
    "https://raw.githubusercontent.com/FGRibreau/mailchecker/refs/heads/master/list.txt"
]

def is_valid_domain(domain):
    """Check if the string is a valid domain."""
    pattern = re.compile(r'^[a-z0-9.-]+\.[a-z]{2,}$')
    if not domain or ' ' in domain or re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        return False
    domain = domain.rstrip('.')
    # Added common placeholder/test domains often found in lists
    if domain in {'zzz.com', 'xxx.com', 'test.com', 'example.com', 'invalid.com'}:
        return False
    # Basic check for invalid characters often seen in bad lists (excluding IDN characters for now)
    # A more robust validation might involve Punycode conversion if IDNs are desired
    if not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$', domain):
         # Allow valid IDN prefixes but the regex above is basic ASCII
         if not domain.startswith('xn--'):
              # print(f"DEBUG: Invalid domain format detected: {domain}") # Optional debug
              return False
    return True


def has_mx_record(domain, main_resolver, fallback_resolver): # Accept both resolvers
    """
    Check if domain has MX records using provided resolver instances.
    Uses main_resolver first, then fallback_resolver if NoNameservers is encountered.
    Returns a tuple: (bool: has_mx, str: status_or_error)
    """
    try:
        # --- Attempt with main resolver ---
        answers = main_resolver.resolve(domain, 'MX')
        if len(answers) > 0:
            if answers[0].preference == 0 and str(answers[0].exchange) == '.':
                 return False, "NullMX"
            return True, "OK"
        else:
            return False, "NoAnswer"
    except dns.resolver.NXDOMAIN:
        return False, "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return False, "NoAnswer"
    except dns.exception.Timeout:
        # Timeout is handled by the resolver's lifetime setting
        return False, "Timeout"
    except dns.resolver.NoNameservers:
        # --- Attempt with fallback resolver ---
        try:
            # DO NOT create a new resolver here. Use the passed-in fallback_resolver.
            fallback_answers = fallback_resolver.resolve(domain, 'MX')
            if len(fallback_answers) > 0:
                if fallback_answers[0].preference == 0 and str(fallback_answers[0].exchange) == '.':
                    return False, "NullMX_Fallback"
                return True, "OK_Fallback"
            else:
               return False, "NoAnswer_Fallback"
        except dns.resolver.NXDOMAIN:
             # If fallback also gets NXDOMAIN, report it specifically if needed, otherwise keep original reason
             return False, "NoNameservers_FallbackNXDOMAIN" # Or stick to "NoNameservers_FallbackFailed"
        except dns.resolver.NoAnswer:
             return False, "NoAnswer_Fallback"
        except dns.exception.Timeout:
             return False, "NoNameservers_FallbackTimeout"
        except Exception as fallback_e:
            # Log the specific fallback error for debugging *if necessary*
            # Make sure logging here doesn't cause issues (e.g., print contention)
            # print(f"DEBUG: Fallback DNS query for {domain} failed: {type(fallback_e).__name__}")
            return False, f"NoNameservers_FallbackFailed:{type(fallback_e).__name__}" # More specific error
    except Exception as e:
        # Catch any other unexpected errors from the main resolver
        return False, f"OtherError:{type(e).__name__}"


def filter_mx_domains(domains):
    """
    Filter domains with MX records using multiple threads and shared Resolvers (main and fallback).
    Returns tuple: (list_of_valid_domains, list_of_dicts_failed_checks)
    """
    mx_checked_domains = []

    # --- Create and configure shared resolvers ---
    main_resolver = dns.resolver.Resolver()
    main_resolver.timeout = 10 # Increased timeout
    main_resolver.lifetime = 10

    fallback_resolver = dns.resolver.Resolver()
    fallback_resolver.nameservers = ['8.8.8.8', '1.1.1.1'] # Google & Cloudflare
    fallback_resolver.timeout = 10 # Increased timeout
    fallback_resolver.lifetime = 10

    # Define the worker function that accepts both resolvers
    def check_domain_worker(domain, resolver_main, resolver_fallback):
        has_mx, status = has_mx_record(domain, resolver_main, resolver_fallback) # Pass both resolvers
        return (domain, has_mx, status)

    # Use ThreadPoolExecutor
    # Start with fewer workers, e.g., 10, to reduce load further
    num_workers = 10 # Reduced worker count
    print(f"Using {num_workers} workers for MX checks.")
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        # Use functools.partial to fix the resolver arguments for the map function
        map_function = functools.partial(check_domain_worker, resolver_main=main_resolver, resolver_fallback=fallback_resolver)

        results_iterator = executor.map(map_function, domains)
        mx_checked_domains = list(tqdm(results_iterator, total=len(domains), desc="Checking MX records"))

    # Separate results
    valid_domains = sorted([d[0] for d in mx_checked_domains if d[1]])
    failed_checks = [{"domain": d[0], "reason": d[2]} for d in mx_checked_domains if not d[1]]

    return valid_domains, failed_checks


def fetch_domains():
    """Fetch disposable email domains from multiple sources."""
    # (Keep the existing fetch_domains logic, ensure it calls the updated filter_mx_domains)
    domains = set()
    log_entries = []
    fetch_errors = []
    invalid_format_domains = []

    print("Starting domain fetching phase...")
    for url in SOURCES:
        try:
            print(f"Fetching: {url}")
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()

            content = resp.text
            source_domains_count = 0
            newly_added_count = 0

            if content.strip().startswith(('[', '{')):
                 try:
                    # Attempt to decode potential UTF-8 BOM
                    if content.startswith('\ufeff'):
                       content = content.lstrip('\ufeff')
                    parsed = json.loads(content)
                    if isinstance(parsed, list):
                        potential_domains = parsed
                    elif isinstance(parsed, dict):
                        potential_domains = parsed.values() # Or keys(), depends on format
                    else:
                        potential_domains = []

                    for item in potential_domains:
                        domain = str(item).strip().lower().rstrip('.')
                        if is_valid_domain(domain):
                            source_domains_count += 1
                            if domain not in domains:
                                domains.add(domain)
                                newly_added_count += 1
                        elif domain:
                            invalid_format_domains.append(f"{domain} (from JSON {url})")
                 except json.JSONDecodeError as e:
                     print(f"Warning: Failed to parse JSON from {url}, attempting line-by-line. Error: {e}")
                     # Fallback for non-JSON or malformed JSON
                     for line in content.splitlines():
                         domain = line.strip().lower().rstrip('.')
                         if domain and not domain.startswith(("#", "//", ";")):
                             if is_valid_domain(domain):
                                 source_domains_count += 1
                                 if domain not in domains:
                                     domains.add(domain)
                                     newly_added_count += 1
                             elif domain:
                                 invalid_format_domains.append(f"{domain} (from Text {url})")
            else:
                # Plain text list
                for line in content.splitlines():
                    domain = line.strip().lower().rstrip('.')
                    if domain and not domain.startswith(("#", "//", ";")):
                        if is_valid_domain(domain):
                            source_domains_count += 1
                            if domain not in domains:
                                domains.add(domain)
                                newly_added_count += 1
                        elif domain:
                            invalid_format_domains.append(f"{domain} (from Text {url})")

            log_entries.append(f"Fetched {source_domains_count} potential domains from {url}, added {newly_added_count} new unique domains.")

        except requests.exceptions.RequestException as e:
            error_msg = f"Failed to fetch {url}: {e}"
            print(error_msg)
            fetch_errors.append(error_msg)
            log_entries.append(error_msg)
        except Exception as e:
            error_msg = f"Error processing data from {url}: {e}"
            print(error_msg)
            fetch_errors.append(error_msg)
            log_entries.append(error_msg)

    # --- Logging Phase ---
    log_filename = f"collector_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    log_path = os.path.join("data", log_filename)
    print(f"Writing detailed log to: {log_path}")

    with open(log_path, "w", encoding='utf-8') as f: # Ensure UTF-8 writing for logs
        f.write("--- GhostMail Collector Log ---\n")
        f.write(f"Run timestamp: {datetime.now().isoformat()}\n")
        f.write("\n--- Fetching Summary ---\n")
        f.write("\n".join(log_entries))
        f.write(f"\n\nTotal unique potential domains collected: {len(domains)}\n")

        if fetch_errors:
            f.write("\n--- Fetching Errors ---\n")
            f.write("\n".join(fetch_errors))

        if invalid_format_domains:
            f.write("\n--- Invalid Domain Formats Excluded (Sample) ---\n")
            # Ensure invalid domains (which might contain non-ASCII) are logged safely
            safe_invalid_domains = [repr(d) for d in invalid_format_domains[:100]]
            f.write("\n".join(safe_invalid_domains))
            if len(invalid_format_domains) > 100:
                 f.write(f"\n...(total {len(invalid_format_domains)} invalid format domains found)")
            f.write("\n")

        f.write("\n--- MX Record Check Phase ---\n")
        f.flush()

        if not domains:
             f.write("No domains collected, skipping MX check.\n")
             print("No domains collected, skipping MX check.")
             return [], []

        domains_list = sorted(list(domains))
        valid_domains, failed_mx_checks = filter_mx_domains(domains_list) # Calls the updated function

        # --- MX Check Logging ---
        f.write(f"Total domains checked for MX records: {len(domains_list)}\n")
        f.write(f"Domains with valid MX records (including fallback): {len(valid_domains)}\n")
        f.write(f"Domains failing MX check (No MX, NXDOMAIN, Timeout, etc.): {len(failed_mx_checks)}\n")

        if failed_mx_checks:
            failure_reasons = Counter(item['reason'] for item in failed_mx_checks)
            f.write("\nSummary of MX Check Failure Reasons:\n")
            for reason, count in sorted(failure_reasons.items()):
                f.write(f"  - {reason}: {count}\n")

            f.write("\nSample of domains failing MX check (up to 100):\n")
            safe_failed_domains = [f"{item['domain']} ({item['reason']})" for item in failed_mx_checks[:100]]
            f.write("\n".join(safe_failed_domains))
            if len(failed_mx_checks) > 100:
                f.write(f"\n...(total {len(failed_mx_checks)} domains failed MX check)")
            f.write("\n")

    print("MX check phase complete.")
    return domains_list, valid_domains


def save_domains(domains, filepath):
    """Save domains to the specified file, one per line."""
    print(f"Saving {len(domains)} domains to {filepath}...")
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    try:
        # Ensure writing with UTF-8 for potentially international domains
        with open(filepath, "w", encoding='utf-8') as f:
            for domain in domains:
                f.write(f"{domain}\n")
        print("Save complete.")
    except IOError as e:
        print(f"Error saving file {filepath}: {e}")

if __name__ == "__main__":
    print("GhostMail Collector starting...")
    data_dir = "data"
    raw_output_path = os.path.join(data_dir, "raw_domains.txt")
    mx_output_path = os.path.join(data_dir, "disposable_emails.txt")

    os.makedirs(data_dir, exist_ok=True)

    all_domains, mx_valid_domains = fetch_domains()

    if all_domains:
        save_domains(all_domains, raw_output_path)
    else:
        print(f"No domains collected, creating empty {raw_output_path}")
        open(raw_output_path, 'w').close()

    if mx_valid_domains:
        save_domains(mx_valid_domains, mx_output_path)
    else:
        print(f"No MX-valid domains found, creating empty {mx_output_path}")
        open(mx_output_path, 'w').close()

    print("-" * 30)
    print("Collector run finished.")
    print(f"Total potential domains fetched (before MX check): {len(all_domains)}")
    print(f"Total domains with valid MX records: {len(mx_valid_domains)}")
    print(f"Raw domain list saved to: {raw_output_path}")
    print(f"MX-validated domain list saved to: {mx_output_path}")
    print(f"Check the data/collector_log_*.txt file for detailed logs.")
    print("-" * 30)
import requests
import os
import json
import re
import functools
import time # Added for sleep in retries
import random # Added for sampling
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

# --- Configuration ---
# Get worker count from environment variable or default to 10
MX_WORKERS = int(os.environ.get('MX_WORKERS', 10))
# DNS Timeouts
DNS_TIMEOUT = int(os.environ.get('DNS_TIMEOUT', 10)) # Increased default
# Retries configuration
RETRY_ATTEMPTS = int(os.environ.get('RETRY_ATTEMPTS', 3)) # Total attempts
RETRY_DELAY = int(os.environ.get('RETRY_DELAY', 2)) # Seconds between retries

def is_valid_domain(domain):
    """Check if the string is a valid domain."""
    pattern = re.compile(r'^[a-z0-9.-]+\.[a-z]{2,}$')
    if not domain or ' ' in domain or re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        return False
    domain = domain.rstrip('.')
    if domain in {'zzz.com', 'xxx.com', 'test.com', 'example.com', 'invalid.com'}:
        return False
    if not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$', domain):
         if not domain.startswith('xn--'):
              # print(f"DEBUG: Invalid domain format detected: {domain}") # Keep commented unless needed
              return False
    return True

def _resolve_with_retries(resolver, domain, record_type='MX'):
    """Internal function to perform DNS resolution with retries for specific errors."""
    last_exception = None
    for attempt in range(RETRY_ATTEMPTS):
        try:
            return resolver.resolve(domain, record_type)
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as e:
            last_exception = e
            if attempt < RETRY_ATTEMPTS - 1:
                # print(f"DEBUG: Attempt {attempt + 1} failed for {domain} with {type(e).__name__}. Retrying in {RETRY_DELAY}s...")
                time.sleep(RETRY_DELAY)
            continue # Go to next attempt
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
            # These are definitive errors, don't retry, re-raise them
            raise e
        except Exception as e:
            # Catch other unexpected errors, don't retry immediately, re-raise
            last_exception = e
            raise e

    # If all retries failed, raise the last captured exception
    # print(f"DEBUG: All {RETRY_ATTEMPTS} attempts failed for {domain}. Last error: {last_exception}")
    raise last_exception


def has_mx_record(domain, main_resolver, fallback_resolver):
    """
    Check if domain has MX records using provided resolver instances with retries.
    Uses main_resolver first, then fallback_resolver if NoNameservers is encountered after retries.
    Returns a tuple: (bool: has_mx, str: status_or_error)
    """
    try:
        # --- Attempt with main resolver (with retries) ---
        answers = _resolve_with_retries(main_resolver, domain, 'MX')
        if len(answers) > 0:
            if answers[0].preference == 0 and str(answers[0].exchange) == '.':
                 return False, "NullMX"
            return True, "OK"
        else:
            return False, "NoAnswer" # Should typically raise NoAnswer exception
    except dns.resolver.NXDOMAIN:
        return False, "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return False, "NoAnswer"
    except dns.exception.Timeout:
        # This Timeout is after retries
        return False, "Timeout"
    except dns.resolver.NoNameservers:
        # Main resolver failed with NoNameservers after retries, try fallback
        # print(f"DEBUG: Main resolver failed (NoNS after retries) for {domain}, trying fallback...")
        try:
            # --- Attempt with fallback resolver (with retries) ---
            fallback_answers = _resolve_with_retries(fallback_resolver, domain, 'MX')
            if len(fallback_answers) > 0:
                if fallback_answers[0].preference == 0 and str(fallback_answers[0].exchange) == '.':
                    return False, "NullMX_Fallback"
                return True, "OK_Fallback"
            else:
               return False, "NoAnswer_Fallback" # Should typically raise NoAnswer
        except dns.resolver.NXDOMAIN:
             return False, "NoNameservers_FallbackNXDOMAIN"
        except dns.resolver.NoAnswer:
             return False, "NoAnswer_Fallback"
        except dns.exception.Timeout:
             return False, "NoNameservers_FallbackTimeout"
        except dns.resolver.NoNameservers:
             # Fallback ALSO failed with NoNameservers after retries
             return False, "NoNameservers_FallbackFailed:NoNameservers"
        except Exception as fallback_e:
             return False, f"NoNameservers_FallbackFailed:{type(fallback_e).__name__}"
    except Exception as e:
        # Catch any other unexpected errors from the main resolver (_resolve_with_retries re-raises them)
        return False, f"OtherError:{type(e).__name__}"

def filter_mx_domains(domains):
    """
    Filter domains with MX records using multiple threads and shared Resolvers with retries.
    Returns tuple: (list_of_valid_domains, list_of_dicts_failed_checks)
    """
    mx_checked_domains = []

    print(f"Config: Workers={MX_WORKERS}, DNS Timeout={DNS_TIMEOUT}s, Retries={RETRY_ATTEMPTS}, Delay={RETRY_DELAY}s")

    main_resolver = dns.resolver.Resolver()
    main_resolver.timeout = DNS_TIMEOUT
    main_resolver.lifetime = DNS_TIMEOUT * RETRY_ATTEMPTS # Allow more total time

    fallback_resolver = dns.resolver.Resolver()
    # Added more fallback resolvers
    fallback_resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222', '208.67.220.220']
    fallback_resolver.timeout = DNS_TIMEOUT
    fallback_resolver.lifetime = DNS_TIMEOUT * RETRY_ATTEMPTS

    def check_domain_worker(domain, resolver_main, resolver_fallback):
        has_mx, status = has_mx_record(domain, resolver_main, resolver_fallback)
        return (domain, has_mx, status)

    print(f"Using {MX_WORKERS} workers for MX checks.")
    with ThreadPoolExecutor(max_workers=MX_WORKERS) as executor:
        map_function = functools.partial(check_domain_worker, resolver_main=main_resolver, resolver_fallback=fallback_resolver)
        results_iterator = executor.map(map_function, domains)
        mx_checked_domains = list(tqdm(results_iterator, total=len(domains), desc="Checking MX records"))

    valid_domains = sorted([d[0] for d in mx_checked_domains if d[1]])
    failed_checks = [{"domain": d[0], "reason": d[2]} for d in mx_checked_domains if not d[1]]

    return valid_domains, failed_checks

def generate_samples(valid_domains, failed_checks, sample_size_ok=50, sample_size_failed=100):
    """Generates a list of domain samples with their status for cross-checking."""
    samples = []
    # Sample OK domains
    ok_sample_list = random.sample(valid_domains, min(sample_size_ok, len(valid_domains)))
    samples.extend([{'domain': d, 'status': 'OK'} for d in ok_sample_list]) # Use 'OK' for all valid ones initially

    # Sample failed domains
    failed_sample_list = random.sample(failed_checks, min(sample_size_failed, len(failed_checks)))
    samples.extend([{'domain': d['domain'], 'status': d['reason']} for d in failed_sample_list])

    # Update status for OK domains that might have used fallback
    ok_fallback_domains = {d['domain'] for d in failed_checks if d['reason'] == 'OK_Fallback'} # Find OK_Fallback in failed (bug here?)
    # Correction: OK_Fallback are actually *in* valid_domains, status is returned by has_mx_record
    # We need to store the actual status returned by has_mx_record for *all* domains if we want precise sampling status
    # For simplicity now, we just label sampled valid domains as 'OK'. The dig check will reveal the truth.

    print(f"Generated {len(samples)} samples for dig cross-check.")
    return samples


def fetch_domains():
    """Fetch disposable email domains from multiple sources."""
    domains = set()
    log_entries = []
    fetch_errors = []
    invalid_format_domains = []

    print("Starting domain fetching phase...")
    # --- (Fetching logic remains the same as the last version) ---
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
                    if content.startswith('\ufeff'):
                       content = content.lstrip('\ufeff')
                    parsed = json.loads(content)
                    if isinstance(parsed, list): potential_domains = parsed
                    elif isinstance(parsed, dict): potential_domains = parsed.values()
                    else: potential_domains = []

                    for item in potential_domains:
                        domain = str(item).strip().lower().rstrip('.')
                        if is_valid_domain(domain):
                            source_domains_count += 1
                            if domain not in domains: domains.add(domain); newly_added_count += 1
                        elif domain: invalid_format_domains.append(f"{domain} (from JSON {url})")
                 except json.JSONDecodeError as e:
                     print(f"Warning: Failed to parse JSON from {url}, attempting line-by-line. Error: {e}")
                     for line in content.splitlines():
                         domain = line.strip().lower().rstrip('.')
                         if domain and not domain.startswith(("#", "//", ";")):
                             if is_valid_domain(domain):
                                 source_domains_count += 1
                                 if domain not in domains: domains.add(domain); newly_added_count += 1
                             elif domain: invalid_format_domains.append(f"{domain} (from Text {url})")
            else: # Plain text list
                for line in content.splitlines():
                    domain = line.strip().lower().rstrip('.')
                    if domain and not domain.startswith(("#", "//", ";")):
                        if is_valid_domain(domain):
                            source_domains_count += 1
                            if domain not in domains: domains.add(domain); newly_added_count += 1
                        elif domain: invalid_format_domains.append(f"{domain} (from Text {url})")

            log_entries.append(f"Fetched {source_domains_count} potential domains from {url}, added {newly_added_count} new unique domains.")

        except requests.exceptions.RequestException as e:
            error_msg = f"Failed to fetch {url}: {e}"; print(error_msg); fetch_errors.append(error_msg); log_entries.append(error_msg)
        except Exception as e:
            error_msg = f"Error processing data from {url}: {e}"; print(error_msg); fetch_errors.append(error_msg); log_entries.append(error_msg)
    # --- (End of fetching logic) ---


    # --- Logging Phase ---
    log_filename = f"collector_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    log_path = os.path.join("data", log_filename)
    print(f"Writing detailed log to: {log_path}")

    # Prepare sample file path
    data_dir = "data"
    sample_output_path = os.path.join(data_dir, "mx_check_samples.json")

    with open(log_path, "w", encoding='utf-8') as f:
        f.write("--- GhostMail Collector Log ---\n")
        f.write(f"Run timestamp: {datetime.now().isoformat()}\n")
        f.write(f"Config: MX_WORKERS={MX_WORKERS}, DNS_TIMEOUT={DNS_TIMEOUT}, RETRY_ATTEMPTS={RETRY_ATTEMPTS}, RETRY_DELAY={RETRY_DELAY}\n") # Log config
        f.write("\n--- Fetching Summary ---\n")
        f.write("\n".join(log_entries))
        f.write(f"\n\nTotal unique potential domains collected: {len(domains)}\n")

        if fetch_errors: f.write("\n--- Fetching Errors ---\n"); f.write("\n".join(fetch_errors))
        if invalid_format_domains:
            f.write("\n--- Invalid Domain Formats Excluded (Sample) ---\n")
            safe_invalid_domains = [repr(d) for d in invalid_format_domains[:100]]
            f.write("\n".join(safe_invalid_domains))
            if len(invalid_format_domains) > 100: f.write(f"\n...(total {len(invalid_format_domains)} invalid format domains found)")
            f.write("\n")

        f.write("\n--- MX Record Check Phase ---\n")
        f.flush()

        if not domains:
             f.write("No domains collected, skipping MX check.\n")
             print("No domains collected, skipping MX check.")
             # Ensure sample file is empty if no domains
             with open(sample_output_path, "w") as sf: json.dump([], sf)
             return [], [], [] # Return empty lists

        domains_list = sorted(list(domains))
        valid_domains, failed_mx_checks = filter_mx_domains(domains_list)

        # --- MX Check Logging ---
        f.write(f"Total domains checked for MX records: {len(domains_list)}\n")
        f.write(f"Domains with valid MX records (including fallback): {len(valid_domains)}\n")
        f.write(f"Domains failing MX check (No MX, NXDOMAIN, Timeout, etc.): {len(failed_mx_checks)}\n")
        if failed_mx_checks:
            failure_reasons = Counter(item['reason'] for item in failed_mx_checks)
            f.write("\nSummary of MX Check Failure Reasons:\n")
            for reason, count in sorted(failure_reasons.items()): f.write(f"  - {reason}: {count}\n")
            f.write("\nSample of domains failing MX check (up to 100):\n")
            safe_failed_domains = [f"{item['domain']} ({item['reason']})" for item in failed_mx_checks[:100]]
            f.write("\n".join(safe_failed_domains))
            if len(failed_mx_checks) > 100: f.write(f"\n...(total {len(failed_mx_checks)} domains failed MX check)")
            f.write("\n")

    print("MX check phase complete.")

    # --- Generate and Save Samples ---
    samples = generate_samples(valid_domains, failed_mx_checks)
    try:
        with open(sample_output_path, "w", encoding='utf-8') as sf:
            json.dump(samples, sf, indent=2)
        print(f"Saved {len(samples)} samples to {sample_output_path}")
    except IOError as e:
        print(f"Error saving samples file {sample_output_path}: {e}")


    return domains_list, valid_domains, samples # Return samples as well


def save_domains(domains, filepath):
    """Save domains to the specified file, one per line."""
    print(f"Saving {len(domains)} domains to {filepath}...")
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    try:
        with open(filepath, "w", encoding='utf-8') as f:
            for domain in domains: f.write(f"{domain}\n")
        print("Save complete.")
    except IOError as e:
        print(f"Error saving file {filepath}: {e}")

if __name__ == "__main__":
    print("GhostMail Collector starting...")
    data_dir = "data"
    raw_output_path = os.path.join(data_dir, "raw_domains.txt")
    mx_output_path = os.path.join(data_dir, "disposable_emails.txt")
    sample_output_path = os.path.join(data_dir, "mx_check_samples.json") # Path for samples

    os.makedirs(data_dir, exist_ok=True)

    # Run main logic, now returns samples too
    all_domains, mx_valid_domains, _ = fetch_domains() # We save samples inside fetch_domains

    # Save the main domain lists
    if all_domains: save_domains(all_domains, raw_output_path)
    else: print(f"No domains collected, creating empty {raw_output_path}"); open(raw_output_path, 'w').close()
    if mx_valid_domains: save_domains(mx_valid_domains, mx_output_path)
    else: print(f"No MX-valid domains found, creating empty {mx_output_path}"); open(mx_output_path, 'w').close()

    print("-" * 30)
    print("Collector run finished.")
    print(f"Total potential domains fetched (before MX check): {len(all_domains)}")
    print(f"Total domains with valid MX records: {len(mx_valid_domains)}")
    print(f"Raw domain list saved to: {raw_output_path}")
    print(f"MX-validated domain list saved to: {mx_output_path}")
    print(f"Check samples saved to: {sample_output_path}")
    print(f"Check the data/collector_log_*.txt file for detailed logs.")
    print("-" * 30)
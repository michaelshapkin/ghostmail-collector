import requests
import os
import json
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import dns.exception
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
    if domain in {'zzz.com', 'xxx.com', 'test.com'}:
        return False
    return bool(pattern.match(domain))

def has_mx_record(domain):
    """Check if domain has MX records."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(domain, 'MX')
        return len(answers) > 0
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return False
    except dns.resolver.NoNameservers:
        try:
            resolver.nameservers = ['8.8.8.8']  # Fallback to Google DNS
            answers = resolver.resolve(domain, 'MX')
            return len(answers) > 0
        except Exception:
            return False
    except Exception:
        return False

def filter_mx_domains(domains):
    """Filter domains with MX records using multiple threads."""
    no_mx_domains = []
    valid_domains = []
    
    def check_domain(domain):
        if has_mx_record(domain):
            return (domain, True)
        else:
            return (domain, False)
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = list(tqdm(executor.map(check_domain, domains), total=len(domains), desc="Checking MX records"))
    
    for domain, has_mx in results:
        if has_mx:
            valid_domains.append(domain)
        else:
            no_mx_domains.append(domain)
    
    return sorted(valid_domains), no_mx_domains

def fetch_domains():
    """Fetch disposable email domains from multiple sources."""
    domains = set()
    log_entries = []
    invalid_domains = []

    for url in SOURCES:
        try:
            print(f"Fetching: {url}")
            resp = requests.get(url, timeout=10)
            if resp.ok:
                content = resp.text
                source_domains = set()
                if content.strip().startswith(('"', '[')):
                    try:
                        parsed = json.loads(content)
                        for item in parsed:
                            domain = str(item).lower().rstrip('.')
                            if is_valid_domain(domain):
                                source_domains.add(domain)
                            else:
                                invalid_domains.append(f"{domain} (from {url})")
                    except Exception as e:
                        print(f"Failed to parse JSON: {e}")
                        log_entries.append(f"Failed to parse JSON from {url}: {e}")
                else:
                    for line in content.splitlines():
                        domain = line.strip().lower().rstrip('.')
                        if domain and not domain.startswith("#"):
                            if is_valid_domain(domain):
                                source_domains.add(domain)
                            else:
                                invalid_domains.append(f"{domain} (from {url})")
                
                unique_to_source = source_domains - domains
                domains.update(source_domains)
                log_entries.append(f"Fetched {len(source_domains)} valid domains from {url} ({len(unique_to_source)} unique)")
            else:
                print(f"Failed to fetch {url}: HTTP {resp.status_code}")
                log_entries.append(f"Failed to fetch {url}: HTTP {resp.status_code}")
        except Exception as e:
            print(f"Error fetching {url}: {e}")
            log_entries.append(f"Error fetching {url}: {e}")

    # Save log
    log_path = os.path.join("data", f"collector_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    with open(log_path, "w") as f:
        f.write("\n".join(log_entries))
        if invalid_domains:
            f.write("\nInvalid domains excluded:\n" + "\n".join(invalid_domains[:100]))
        f.write("\nStarting MX record check...\n")

    domains = sorted(domains)
    valid_domains, no_mx_domains = filter_mx_domains(domains)
    
    # Append MX check results to log
    with open(log_path, "a") as f:
        f.write(f"Total domains checked: {len(domains)}\n")
        f.write(f"Domains with MX records: {len(valid_domains)}\n")
        f.write(f"Domains without MX records: {len(no_mx_domains)}\n")
        if no_mx_domains:
            f.write("Sample of domains without MX records (up to 100):\n" + "\n".join(no_mx_domains[:100]))

    return domains, valid_domains

def save_domains(domains, filepath):
    """Save domains to the specified file."""
    with open(filepath, "w") as f:
        for domain in domains:
            f.write(f"{domain}\n")

if __name__ == "__main__":
    raw_output_path = os.path.join("data", "raw_domains.txt")
    final_output_path = os.path.join("data", "disposable_emails.txt")
    all_domains, valid_domains = fetch_domains()
    save_domains(all_domains, raw_output_path)
    save_domains(valid_domains, final_output_path)
    print(f"Saved {len(all_domains)} domains to {raw_output_path}")
    print(f"Saved {len(valid_domains)} domains to {final_output_path}")
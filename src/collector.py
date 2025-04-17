import requests
import os
import json
import re
from datetime import datetime
import dns.resolver

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
    # Exclude suspicious generic domains
    if domain in {'zzz.com', 'xxx.com', 'test.com'}:
        return False
    return bool(pattern.match(domain))

def has_mx_record(domain, timeout=5):
    """Check if domain has an MX record."""
    try:
        dns.resolver.resolve(domain, 'MX', lifetime=timeout)
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return False

def fetch_domains():
    """Fetch disposable email domains from multiple sources."""
    domains = set()
    log_entries = []
    invalid_domains = []
    no_mx_domains = []

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
                
                # Sample MX check for up to 10 domains
                sample_size = min(10, len(source_domains))
                sample = list(source_domains)[:sample_size]
                no_mx_sample = [d for d in sample if not has_mx_record(d)]
                if no_mx_sample:
                    log_entries.append(f"Warning: {len(no_mx_sample)}/{sample_size} sampled domains from {url} have no MX records: {', '.join(no_mx_sample[:5])}")
                    no_mx_domains.extend(f"{d} (from {url})" for d in no_mx_sample)
                
                # Calculate unique domains added by this source
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
        if no_mx_domains:
            f.write("\nDomains without MX records (sampled):\n" + "\n".join(no_mx_domains[:100]))

    return sorted(domains)

def save_domains(domains, filepath):
    """Save domains to the specified file."""
    with open(filepath, "w") as f:
        for domain in domains:
            f.write(f"{domain}\n")

if __name__ == "__main__":
    output_path = os.path.join("data", "disposable_emails.txt")
    all_domains = fetch_domains()
    save_domains(all_domains, output_path)
    print(f"Saved {len(all_domains)} domains to {output_path}")
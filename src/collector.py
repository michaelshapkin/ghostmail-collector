import requests
import os

SOURCES = [
    "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf",
    "https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json",
    "https://api.tremendous.com/prohibited_email_domains.txt"
]

def fetch_domains():
    domains = set()

    for url in SOURCES:
        try:
            print(f"Fetching: {url}")
            resp = requests.get(url, timeout=10)
            if resp.ok:
                content = resp.text
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if line.startswith('"') or line.startswith("["):
                            try:
                                import json
                                parsed = json.loads(content)
                                domains.update(parsed)
                                break
                            except Exception as e:
                                print(f"Failed to parse JSON: {e}")
                        else:
                            domains.add(line.lower())
        except Exception as e:
            print(f"Error fetching {url}: {e}")

    return sorted(domains)

def save_domains(domains, filepath):
    with open(filepath, "w") as f:
        for domain in domains:
            f.write(f"{domain}\n")

if __name__ == "__main__":
    output_path = os.path.join("data", "disposable_emails.txt")
    all_domains = fetch_domains()
    save_domains(all_domains, output_path)
    print(f"Saved {len(all_domains)} domains to {output_path}")

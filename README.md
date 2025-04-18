# GhostMail Collector 👻📧

![Auto Update](https://github.com/michaelshapkin/ghostmail-collector/actions/workflows/updater.yml/badge.svg)

> A curated, auto-updated open-source list of disposable email domains used in spam, bots, and temporary email services.

---

## 🚀 What is this?

GhostMail Collector is a powerful, automated tool that compiles and maintains the most comprehensive list of disposable email domains. It fetches, validates, and deduplicates domains from trusted open-source repositories, ensuring high accuracy for:

- Email validation
- Anti-spam filters
- User registration checks
- Integration into SaaS, backends, or APIs

The list is updated **daily** via GitHub Actions and stored in two formats:
- 📄 `data/raw_domains.txt`: All collected domains (~180K).
- 📄 `data/disposable_emails.txt`: Domains with valid MX records (~32K).

---

## 📋 Output Files

- **`data/raw_domains.txt`**: Complete, deduplicated list of disposable email domains from all sources (~180,000 domains).
- **`data/disposable_emails.txt`**: Filtered list of domains with valid MX records, ideal for strict email validation (~32,000 domains).
- **`data/collector_log_*.txt`**: Logs detailing fetch results, MX checks, and excluded domains.

Both `.txt` files are plain text, one domain per line, ready for integration.

---

## ⚙️ How it works

1. A Python script fetches domains from multiple open-source repositories.
2. Domains are cleaned, deduplicated, and validated for format.
3. MX records are checked to filter domains with active email capabilities.
4. GitHub Actions runs the script daily at 04:00 UTC.
5. Results are committed to `data/raw_domains.txt` and `data/disposable_emails.txt`.

---

## 📡 Sources

The collector aggregates domains from the following trusted sources:

- [disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains): Comprehensive blocklist of disposable email domains.
- [ivolo/disposable-email-domains](https://github.com/ivolo/disposable-email-domains): Extensive JSON-based disposable domain list.
- [Tremendous API](https://api.tremendous.com/prohibited_email_domains.txt): Prohibited email domains for financial services.
- [disposable/disposable-email-domains](https://github.com/disposable/disposable-email-domains): Curated lists (standard and strict) of temporary email domains.
- [StopForumSpam](https://www.stopforumspam.com/downloads/toxic_domains_whole.txt): Toxic domains used in spam activities.
- [adamloving/temporary-email-address-domains](https://gist.githubusercontent.com/adamloving/4401361/raw): Gist of temporary email domains.
- [unkn0w/disposable-email-domain-list](https://github.com/unkn0w/disposable-email-domain-list): Community-maintained disposable domain list.
- [GeroldSetz/emailondeck.com-domains](https://github.com/GeroldSetz/emailondeck.com-domains): Domains from emailondeck.com.
- [FGRibreau/mailchecker](https://github.com/FGRibreau/mailchecker): Broad list of disposable email domains.

---

## 🛠️ How to run locally

1. Clone the repository:
   ```bash
   git clone https://github.com/michaelshapkin/ghostmail-collector.git
   cd ghostmail-collector
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the collector:
   ```bash
   python src/collector.py
   ```

4. Check outputs in `data/`:
   - `raw_domains.txt`
   - `disposable_emails.txt`
   - `collector_log_*.txt`

---


### 📊 Stats

- **Total domains:** ~180,000 (deduplicated across all sources)
- **MX-validated domains:** ~4,600 (domains confirmed with active MX records via strict check)
- **Update frequency:** Daily at 04:00 UTC (via GitHub Actions)
- **Processing time:** ~30–40 minutes (fetching + MX checks using 10 workers)
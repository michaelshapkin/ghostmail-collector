# GhostMail Collector 👻📧

![Auto Update](https://github.com/michaelshapkin/ghostmail-collector/actions/workflows/updater.yml/badge.svg)

> A curated, auto-updated open-source list of disposable email domains used in spam, bots, and temporary email services.

---

## 🚀 What is this?

GhostMail Collector is a GitHub-powered utility that **collects, deduplicates, and auto-updates** the most complete list of disposable (temporary) email domains on the web.

This repository is updated **daily** via GitHub Actions and includes known domains from a variety of trusted sources.

---

## 📋 List of disposable email domains

You can find the full list here:
➡️ [data/disposable_emails.txt](data/disposable_emails.txt)

Plain `.txt` file, one domain per line, ready for:

- Email validation
- Anti-spam filters
- User registration checks
- Integrating into SaaS / backend / API logic

---

## ⚙️ How it works

1. Python script fetches data from multiple open-source repositories.
2. Domains are extracted, cleaned, and deduplicated.
3. GitHub Actions runs the script automatically every 24h.
4. Cleaned output is committed to this repo in `data/disposable_emails.txt`.

---

## 📡 Sources

Currently pulling from:

- https://github.com/disposable-email-domains/disposable-email-domains
- https://github.com/ivolo/disposable-email-domains
- https://api.tremendous.com/prohibited_email_domains.txt
- More coming soon…

PRs with new sources welcome!

---

## 🛠️ How to run locally

```bash
python src/collector.py

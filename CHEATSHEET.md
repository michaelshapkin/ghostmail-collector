# GhostMail Collector - Cheatsheet 👻📝

A quick reference guide for setting up, running, testing, and maintaining the GhostMail Collector project.

## Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/michaelshapkin/ghostmail-collector.git
    cd ghostmail-collector
    ```
2.  **Create and activate a virtual environment:**
    ```bash
    # Create (use the Python version you intend to use, e.g., 3.11+)
    python -m venv venv
    # Activate (macOS/Linux)
    source venv/bin/activate
    # Activate (Windows)
    # venv\Scripts\activate
    ```
3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

---
## Local Development

### Run the Collector

*   Execute the main script to fetch domains and check MX records:
    ```bash
    python src/collector.py
    ```
*   Outputs will be generated in the `data/` directory:
    *   `data/raw_domains.txt`: All unique domains found.
    *   `data/disposable_emails.txt`: Domains with validated MX records.
    *   `data/collector_log_YYYYMMDD_HHMMSS.txt`: Detailed log of the run.
    *   `data/mx_check_samples.json`: Sample domains and their statuses (for potential debugging/cross-check).

### Run Tests

*   Execute the test suite using pytest (ensure test dependencies are installed):
    ```bash
    # Always use 'python -m pytest' to ensure correct environment/paths
    python -m pytest
    ```
*   Run specific tests using keywords (`-k`):
    ```bash
    python -m pytest -k "is_valid_domain"
    python -m pytest -k "has_mx_record and ok" # Run tests with 'has_mx_record' AND 'ok' in name
    ```
*   Test configuration is in `pyproject.toml`. Tests are located in the `tests/` directory.

---
## Git & GitHub Workflow

This project uses a feature branch workflow with Pull Requests.

1.  **Ensure `main` is up-to-date:**
    ```bash
    git checkout main
    git pull origin main
    ```
2.  **Create a new feature branch:**
    ```bash
    # Start from main
    git checkout -b <your-branch-name>
    # Example: git checkout -b feature/improve-parsing
    ```
3.  **Make changes, add, and commit:**
    ```bash
    # Make your code changes...
    git status # Check changes
    git add . # Add all changes (or specific files)
    git commit -m "feat: Describe your change briefly"
    ```
4.  **Keep branch updated (optional, if `main` changed):**
    ```bash
    # While on your branch:
    git fetch origin # Get latest info from remote
    git merge origin/main # Merge latest main into your branch
    # Resolve conflicts if they occur
    ```
    *Or rebase (advanced):* `git rebase origin/main`
5.  **Push your branch to GitHub:**
    ```bash
    git push origin <your-branch-name>
    # Use -u for the first push: git push -u origin <your-branch-name>
    ```
6.  **Create a Pull Request (PR) on GitHub:**
    *   Go to the repository on GitHub.
    *   Click "Compare & pull request" for your branch.
    *   Set `base: main` <- `compare: <your-branch-name>`.
    *   Add a title and description.
    *   Create the PR.
7.  **Code Review & Checks:**
    *   Wait for automated checks (like the "Run Python Tests" workflow) to pass.
    *   Address any review comments if applicable.
8.  **Merge PR:**
    *   Once approved and checks pass, click "Merge pull request" on GitHub.
9.  **Clean up:**
    *   Update local `main`:
        ```bash
        git checkout main
        git pull origin main
        ```
    *   Delete local branch:
        ```bash
        git branch -d <your-branch-name>
        ```
    *   Delete remote branch (optional, can be done via GitHub UI):
        ```bash
        git push origin --delete <your-branch-name>
        ```
---

## GitHub Actions

Workflows are defined in `.github/workflows/`.

*   **`updater.yml`**:
    *   Runs daily (`schedule`) or manually (`workflow_dispatch`).
    *   Fetches domains, runs `src/collector.py`, commits results to `data/`.
    *   Runs `dig` cross-check on samples.
    *   Creates a diff artifact.
    *   **Manual Run:** Go to Actions -> "Update Disposable Email List" -> "Run workflow". Can specify branch and parameters (`MX_WORKERS`, `DNS_TIMEOUT`, etc.).
*   **`tests.yml`**:
    *   Runs automatically on pushes/PRs to `main`.
    *   Runs `pytest` using `python -m pytest` on specified Python versions (currently 3.13).
    *   **Manual Run:** Go to Actions -> "Run Python Tests" -> "Run workflow". Can specify branch.

---

## Project Structure

```text
.
+-- .github/workflows/  # GitHub Actions workflows
|   +-- updater.yml
|   L-- tests.yml
+-- data/               # Output data (mostly ignored except for committed lists)
|   +-- disposable_emails.txt  # Validated MX domains (COMMITTED)
|   +-- raw_domains.txt        # All collected domains (COMMITTED)
|   L-- .gitignore             # Ignores logs, samples etc. in data/
+-- src/                # Source code
|   L-- collector.py
+-- tests/              # Pytest tests
|   +-- __init__.py
|   L-- test_collector.py
+-- .gitignore          # Git ignore rules for the root
+-- CHEATSHEET.md       # This file
+-- LICENSE             # Project license (Consider adding one!)
+-- README.md           # Project description
+-- requirements.txt    # Python dependencies
L-- pyproject.toml      # Project config (includes pytest settings)
```
---

## Common Issues / Troubleshooting

*   **Tests fail in CI but pass locally:**
    *   Check dependency version differences (`pip freeze` locally vs. installed in CI).
    *   Ensure `PYTHONPATH=src python -m pytest` is used in CI workflow (`tests.yml`) to find the `collector` module.
*   **`ModuleNotFoundError: No module named 'collector'` when running pytest:**
    *   Run using `python -m pytest` from the project root.
    *   Ensure `pyproject.toml` has the correct `pythonpath`.
    *   If running in CI, ensure `PYTHONPATH=src` is set (see `tests.yml`).
*   **`OSError: [Errno 24] Too many open files` during MX check:**
    *   Caused by creating too many `dns.resolver.Resolver` instances concurrently.
    *   **Fix:** Use shared resolver instances passed to worker threads (as implemented). Reduce `MX_WORKERS` environment variable if necessary (default is 10).
*   **Merge Conflicts:**
    *   Usually happen in `data/*.txt` files if the bot updated `main` while you were working on a branch.
    *   During `git merge main`:
        *   Open the conflicting file.
        *   Edit to keep the desired version (usually yours: keep lines between `<<<<<<< HEAD` and `=======`, delete the rest including markers).
        *   Or use `git checkout --ours <filename>` to keep your version.
        *   `git add <filename>`
        *   `git commit` to finalize the merge.

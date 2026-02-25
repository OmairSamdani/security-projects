# Basic Malware Hash Checker (Python)

A beginner-friendly Python tool that scans files or folders and checks their MD5 and SHA-256 hashes against a list of known malicious hashes.

---

## Features

- Scan a single file or an entire folder
- Generates SHA-256 and MD5 hashes for each file
- Compares hashes against a `malicious_hashes.txt` database
- Alerts if a file is detected as malicious
- Allows repeated scanning with a simple yes/no prompt
- Color-coded output for readability (red = malicious, green = clean)

---

## How To Run

1. Make sure Python 3 is installed.
2. Place `main.py`, `malicious_hashes.txt`, and a test folder (e.g., `test_files/`) in the same directory.
3. Run the script:

```bash
python main.py

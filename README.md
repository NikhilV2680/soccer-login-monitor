# Soccer Login Alert System

## What is this?

This is a Python project that scans soccer player login data for suspicious activity. It looks for things like:

- Logins happening too early (before 6 AM)
- Multiple failed login attempts by the same user
- Unknown users logging in who aren’t on the official player list
- Logins from private IP addresses (like home or local networks)
- Logins from IPs that appear on a known blacklist of suspicious or malicious IP addresses

The script processes a CSV file of login records, analyzes it, and writes alerts to organized files so you can quickly spot potential security concerns.

---

## Why did I build this?

To learn and demonstrate how to combine data parsing, IP threat intelligence, and simple security checks — all wrapped in clean, readable Python code. It’s a great starting point for real-world log monitoring and alerting.

---

## How does it work?

1. Reads a CSV file with login data (`soccer_logins.csv`).
2. Checks each login:
   - Counts failed login attempts per user.
   - Flags early logins before 6 AM.
   - Checks if the username is in the known list of players.
   - Detects if the IP address is private.
   - Checks if the IP is on a blacklist.
3. Writes all alerts into different text files inside an `alerts/` folder, grouped by alert type:
   - General alerts (failed logins, early logins, unknown users)
   - Private IP login alerts
   - Blacklisted IP login alerts

---

## How to get started

1. Make sure you have Python 3 installed.

2. Clone or download this repository.

3. Put your login CSV file (`soccer_logins.csv`) into the `data/` folder.

4. Make sure you have the `ip_blacklist.txt` file in the project root (this contains IPs known to be suspicious).

5. Run the main script:

   ```bash
   python main.py

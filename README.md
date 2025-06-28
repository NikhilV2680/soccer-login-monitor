# Soccer Login Alert System & Simulation

## What is this?

This Python project monitors soccer player login data for suspicious activity and also lets you simulate login attempts via a simple web app.

It can:

- Detect early logins (before 6 AM)  
- Track repeated failed login attempts  
- Spot unknown or unrecognized usernames  
- Identify logins from private IP addresses (e.g., local/home networks)  
- Flag logins from known blacklisted IP addresses  
- Simulate login attempts with username/password inputs that always fail (for security testing)  
- Lock out users for 30 minutes after 3 failed login tries  
- Log every login attempt with timestamp, username, and result  

---

## Why did I build this?

To practice real-world cybersecurity and monitoring concepts using Python and Streamlit — combining data parsing, IP checks, user authentication simulation, and alert generation. This project is a solid foundation for understanding login security monitoring in a simple, practical way.

---

## How does it work?

1. You upload or provide a CSV login file (`soccer_logins.csv`) containing login records.

2. The system analyzes each login for:  
   - Early logins  
   - Failed attempts and how many times per user  
   - Unknown usernames  
   - Private IP addresses usage  
   - Blacklisted IP addresses  

3. Alerts are generated and saved into organized text files inside the `alerts/` folder.

4. You can also open the Streamlit web app, enter any username and password, and simulate login attempts that always fail.

5. After 3 failed attempts from the same username, the user is locked out for 30 minutes.

6. All simulated login attempts and lockouts are logged for audit.

---

## Getting Started

### Requirements

- Python 3.7+  
- Streamlit (`pip install streamlit`)  

### Setup

1. Clone or download this repo.

2. Place your `soccer_logins.csv` file inside the project folder (or upload it via the web app).

3. Make sure you have `ip_blacklist.txt` in the root folder (contains IPs to flag).

4. Run the monitoring script locally:

   ```bash
   python main.py

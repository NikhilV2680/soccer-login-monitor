import csv
import datetime
import ipaddress
import os
import io
import json
import streamlit as st

# Known authorized soccer players
known_users = {
    'Ronaldo', 'Messi', 'Neymar', 'Hazard', 'Mbappe', 'Salah', 'Lewandowski', 'Kane', 'DeBruyne', 'Modric',
    'Sterling', 'Sancho', 'Pogba', 'Griezmann', 'Alcantara', 'Muller', 'Verratti', 'Aguero', 'Coutinho', 'Dybala',
    'Haaland', 'Foden', 'Jesus', 'Grealish', 'Kroos', 'Bale', 'Benzema', 'Silva', 'Rashford', 'Insigne',
    'Alli', 'Mahrez', 'Sane', 'Firmino', 'Ziyech', 'Davidson', 'Thiago', 'Walker', 'Cancelo', 'Rodri',
    'Eriksen', 'Sané', 'Alonso', 'Godin', 'Kimmich', 'de Ligt', 'Varane', 'Marquinhos', 'Fernandinho', 'Laporte'
}

# Ensure alerts folder exists for logs
os.makedirs('alerts', exist_ok=True)

# Path for login attempts and lockout tracking
log_file_path = "alerts/login_attempts.txt"
lockout_file = "alerts/lockout.json"

# Load or initialize lockout data
if os.path.exists(lockout_file):
    with open(lockout_file, "r") as f:
        lockout_data = json.load(f)
else:
    lockout_data = {}

def load_attempts():
    """Load login attempts from log file."""
    attempts = {}
    if os.path.exists(log_file_path):
        with open(log_file_path, "r") as f:
            for line in f:
                try:
                    timestamp_str, status, user = line.strip().split(" | ")
                    timestamp = datetime.datetime.fromisoformat(timestamp_str)
                    attempts.setdefault(user, []).append((timestamp, status))
                except:
                    continue
    return attempts

def log_attempt(status, username):
    """Log a login attempt."""
    with open(log_file_path, "a") as f:
        f.write(f"{datetime.datetime.now().isoformat()} | {status} | {username}\n")

def save_lockouts():
    """Save lockout info to file."""
    with open(lockout_file, "w") as f:
        json.dump(lockout_data, f)

def process_login_file(uploaded_file):
    """Process uploaded CSV file for soccer login alerts."""
    failed_attempts = {}
    attempt_times = {}

    content = uploaded_file.read().decode("utf-8")
    f = io.StringIO(content)
    reader = csv.DictReader(f)
    rows = list(reader)

    for row in rows:
        username = row['username']
        success = row['success'].lower()
        timestamp = row['timestamp']
        if success == 'false':
            failed_attempts[username] = failed_attempts.get(username, 0) + 1
            attempt_times.setdefault(username, []).append(timestamp)

    # Write general alerts
    with open('alerts/alerts.txt', 'w') as alert_file:
        for row in rows:
            username = row['username']
            timestamp_str = row['timestamp']
            dt = datetime.datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
            hour = dt.hour

            is_unknown = username not in known_users
            is_early = hour < 6

            if is_early and is_unknown:
                alert_file.write(f"ALERT: Unknown user {username} logged in very early at {timestamp_str}\n")
            elif is_early:
                alert_file.write(f"Alert: {username} logged in early at {dt.strftime('%H:%M')}\n")
            elif is_unknown:
                alert_file.write(f"Alert: Unknown user {username} logged in at {dt.strftime('%Y-%m-%d %H:%M')}\n")

        for user, count in failed_attempts.items():
            if count >= 3:
                timestamps = ', '.join(attempt_times[user])
                alert_file.write(f"Alert: {user} had {count} failed login attempts at these times: {timestamps}\n")

    # Private IP alerts
    with open('alerts/private_ip_alerts.txt', 'w') as alert_file:
        for row in rows:
            username = row['username']
            ip_str = row.get('ip', '').strip()
            timestamp_str = row['timestamp']

            try:
                ip_obj = ipaddress.ip_address(ip_str)
                dt = datetime.datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
                hour = dt.hour

                if ip_obj.is_private:
                    if username in known_users and (hour < 8 or hour >= 20):
                        alert_file.write(f"Suspicious: {username} used private IP {ip_str} at {timestamp_str} (odd hour)\n")
                    elif username in known_users:
                        alert_file.write(f"Info: {username} used private IP {ip_str} at {timestamp_str}\n")
                    else:
                        alert_file.write(f"Alert: Unknown user {username} used private IP {ip_str} at {timestamp_str}\n")
            except ValueError:
                continue

    # Blacklisted IP alerts
    try:
        with open('ip_blacklist.txt', 'r') as file:
            blacklisted_ips = set(line.strip() for line in file if line.strip() and not line.startswith('#'))
    except FileNotFoundError:
        blacklisted_ips = set()

    blacklist_networks = []
    for ip_entry in blacklisted_ips:
        try:
            net = ipaddress.ip_network(ip_entry if '/' in ip_entry else ip_entry + '/32', strict=False)
            blacklist_networks.append(net)
        except ValueError:
            continue

    with open('alerts/blacklist_alerts.txt', 'w') as alert_file:
        for row in rows:
            ip_raw = row.get('ip')
            if not ip_raw:
                continue
            ip = ip_raw.strip()
            username = row.get('username', 'Unknown')
            timestamp = row.get('timestamp', 'Unknown')

            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                continue

            if any(ip_obj in network for network in blacklist_networks):
                alert_file.write(f"Alert: {username} logged in from blacklisted IP {ip} at {timestamp}\n")

# Streamlit UI

st.title("Soccer Login Monitor")

# File uploader for CSV login logs
uploaded_file = st.file_uploader("Upload soccer_logins.csv file", type=['csv'])

if uploaded_file is not None:
    process_login_file(uploaded_file)
    st.success("Alerts have been generated and saved in the alerts/ folder.")

    def show_alerts(title, filepath):
        st.subheader(title)
        try:
            with open(filepath, 'r') as f:
                content = f.read().strip()
                if content:
                    st.text(content)
                else:
                    st.info("No alerts found.")
        except FileNotFoundError:
            st.warning("Alert file not found.")

    show_alerts("General Alerts", 'alerts/alerts.txt')
    show_alerts("Private IP Alerts", 'alerts/private_ip_alerts.txt')
    show_alerts("Blacklisted IP Alerts", 'alerts/blacklist_alerts.txt')

# Login Simulation UI

st.header("Login Simulation")

st.write("Enter username and password to simulate login attempts.")

username = st.text_input("Username")
password = st.text_input("Password", type="password")

if username:
    now = datetime.datetime.now()
    user_attempts = load_attempts().get(username, [])
    failures = [t for t, s in user_attempts if s == "failed"]

    # Check if user is locked out
    locked_until = lockout_data.get(username)
    if locked_until and datetime.datetime.fromisoformat(locked_until) > now:
        st.error(f"Your account is locked until {locked_until}")
    else:
        if st.button("Login"):
            # Log a failed login attempt (simulate all logins failing)
            log_attempt("failed", username)

            if len(failures) + 1 >= 3:
                lock_until_time = now + datetime.timedelta(minutes=30)
                lockout_data[username] = lock_until_time.isoformat()
                save_lockouts()
                st.error("Too many failed attempts. You are locked out for 30 minutes.")
            else:
                st.error("Login failed.")

# Show login attempts log
st.subheader("Login Attempts Log")
if os.path.exists(log_file_path):
    with open(log_file_path, "r") as f:
        st.text(f.read())
else:
    st.info("No login attempts recorded yet.")

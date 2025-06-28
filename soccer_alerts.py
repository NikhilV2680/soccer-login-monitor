import csv
import datetime
import ipaddress
import os
import streamlit as st

# List of known users (players)
known_users = {
    'Ronaldo', 'Messi', 'Neymar', 'Hazard', 'Mbappe', 'Salah', 'Lewandowski', 'Kane', 'DeBruyne', 'Modric',
    'Sterling', 'Sancho', 'Pogba', 'Griezmann', 'Alcantara', 'Muller', 'Verratti', 'Aguero', 'Coutinho', 'Dybala',
    'Haaland', 'Foden', 'Jesus', 'Grealish', 'Kroos', 'Bale', 'Benzema', 'Silva', 'Rashford', 'Insigne',
    'Alli', 'Mahrez', 'Sane', 'Firmino', 'Ziyech', 'Davidson', 'Thiago', 'Walker', 'Cancelo', 'Rodri',
    'Eriksen', 'Sané', 'Alonso', 'Godin', 'Kimmich', 'de Ligt', 'Varane', 'Marquinhos', 'Fernandinho', 'Laporte'
}

# Create the alerts folder if it doesn't exist, so we can save alert files safely
os.makedirs('alerts', exist_ok=True)

def process_login_file(uploaded_file):
    # Dictionary to count failed login attempts per user
    failed_attempts = {}
    # Dictionary to keep timestamps of failed attempts for reporting
    attempt_times = {}

    # Read CSV rows from uploaded file
    reader = csv.DictReader(uploaded_file)
    rows = list(reader)

    # Count failed login attempts and store their timestamps
    for row in rows:
        username = row['username']
        success = row['success'].lower()
        timestamp = row['timestamp']
        if success == 'false':
            failed_attempts[username] = failed_attempts.get(username, 0) + 1
            attempt_times.setdefault(username, []).append(timestamp)

    # Write alerts for early logins, unknown users, and repeated failed attempts
    with open('alerts/alerts.txt', 'w') as alert_file:
        for row in rows:
            username = row['username']
            timestamp_str = row['timestamp']
            dt_object = datetime.datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
            hour = dt_object.hour

            is_unknown = username not in known_users
            is_early = hour < 6

            # Combine alerts for early logins by unknown users
            if is_early and is_unknown:
                alert_file.write(f"ALERT: Unknown user {username} logged in very early at {timestamp_str}\n")
            elif is_early:
                alert_file.write(f"Alert: {username} logged in early at {dt_object.strftime('%H:%M')}\n")
            elif is_unknown:
                alert_file.write(f"Alert: Unknown user {username} logged in at {dt_object.strftime('%Y-%m-%d %H:%M')}\n")

        # Alert if a user had 3 or more failed login attempts, with timestamps
        for user, count in failed_attempts.items():
            if count >= 3:
                timestamps = ', '.join(attempt_times[user])
                alert_file.write(f"Alert: {user} had {count} failed login attempts at these times: {timestamps}\n")

    # Check and alert for private IP usage
    with open('alerts/private_ip_alerts.txt', 'w') as alert_file:
        for row in rows:
            username = row['username']
            ip_str = row.get('ip', '').strip()
            timestamp_str = row['timestamp']
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                dt_object = datetime.datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
                hour = dt_object.hour

                if ip_obj.is_private:
                    if username in known_users and (hour < 8 or hour >= 20):
                        alert_file.write(f"Suspicious: {username} used private IP {ip_str} at {timestamp_str} (odd hour)\n")
                    elif username in known_users:
                        alert_file.write(f"Info: {username} used private IP {ip_str} at {timestamp_str}\n")
                    else:
                        alert_file.write(f"Alert: Unknown user {username} used private IP {ip_str} at {timestamp_str}\n")
            except ValueError:
                # Skip invalid IP addresses
                continue

    # Load IP blacklist entries from file
    with open('ip_blacklist.txt', 'r') as file:
        blacklisted_ips = set(
            line.strip() for line in file if line.strip() and not line.startswith('#')
        )

    blacklist_networks = []
    for ip_entry in blacklisted_ips:
        try:
            # Support single IPs and CIDR ranges
            network = ipaddress.ip_network(ip_entry if '/' in ip_entry else ip_entry + '/32', strict=False)
            blacklist_networks.append(network)
        except ValueError:
            # Skip invalid entries
            continue

    # Alert if login came from blacklisted IPs
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

# Upload CSV file for analysis
uploaded_file = st.file_uploader("Upload soccer_logins.csv file", type=['csv'])

# Process the file once uploaded
if uploaded_file is not None:
    process_login_file(uploaded_file)
    st.success("Alerts have been generated and saved in the alerts/ folder.")

    # Function to display alert content inside the app
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

    # Show all alert types in the app
    show_alerts("General Alerts", 'alerts/alerts.txt')
    show_alerts("Private IP Alerts", 'alerts/private_ip_alerts.txt')
    show_alerts("Blacklisted IP Alerts", 'alerts/blacklist_alerts.txt')

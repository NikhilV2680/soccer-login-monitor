import csv
import datetime
import ipaddress
import os
import streamlit as st

# ✅ Recognized users who are allowed to log in
known_users = {
    'Ronaldo', 'Messi', 'Neymar', 'Hazard', 'Mbappe', 'Salah', 'Lewandowski', 'Kane', 'DeBruyne', 'Modric',
    'Sterling', 'Sancho', 'Pogba', 'Griezmann', 'Alcantara', 'Muller', 'Verratti', 'Aguero', 'Coutinho', 'Dybala',
    'Haaland', 'Foden', 'Jesus', 'Grealish', 'Kroos', 'Bale', 'Benzema', 'Silva', 'Rashford', 'Insigne',
    'Alli', 'Mahrez', 'Sane', 'Firmino', 'Ziyech', 'Davidson', 'Thiago', 'Walker', 'Cancelo', 'Rodri',
    'Eriksen', 'Sané', 'Alonso', 'Godin', 'Kimmich', 'de Ligt', 'Varane', 'Marquinhos', 'Fernandinho', 'Laporte'
}

# Make sure alerts/ folder exists
os.makedirs('alerts', exist_ok=True)

def process_login_file(uploaded_file):
    failed_attempts = {}
    attempt_times = {}

    reader = csv.DictReader(uploaded_file)
    rows = list(reader)

    # Track login failures per user
    for row in rows:
        username = row['username']
        success = row['success'].lower()
        timestamp = row['timestamp']
        if success == 'false':
            failed_attempts[username] = failed_attempts.get(username, 0) + 1
            attempt_times.setdefault(username, []).append(timestamp)

    # Write alerts for suspicious login behavior
    with open('alerts/alerts.txt', 'w') as alert_file:
        for row in rows:
            username = row['username']
            timestamp_str = row['timestamp']
            dt_object = datetime.datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
            hour = dt_object.hour
            unknown = username not in known_users
            early = hour < 6

            if early and unknown:
                alert_file.write(f"⏰❗ ALERT: Unknown user {username} logged in super early at {timestamp_str}\n")
            elif early:
                alert_file.write(f"⏰ Alert: {username} logged in super early at {dt_object.strftime('%H:%M')}\n")
            elif unknown:
                alert_file.write(f"❗ ALERT: Unknown user {username} logged in at {dt_object.strftime('%Y-%m-%d %H:%M')}\n")

        for user, count in failed_attempts.items():
            if count >= 3:
                timestamps = ', '.join(attempt_times[user])
                alert_file.write(f"🚨 ALERT: {user} had {count} failed login attempts at these times: {timestamps}\n")

    # Check for private IP usage
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
                        alert_file.write(f"⚠️ Suspicious: {username} used private IP {ip_str} at {timestamp_str} (odd hour)\n")
                    elif username in known_users:
                        alert_file.write(f"Info: {username}_

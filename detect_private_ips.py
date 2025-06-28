import csv
import ipaddress
import datetime
import os

# Make sure the alerts folder exists
os.makedirs('alerts', exist_ok=True)

with open('soccer_logins.csv', 'r') as csv_file, open('alerts/private_ip_alerts.txt', 'w') as alert_file:
    reader = csv.DictReader(csv_file)

    for row in reader:
        username = row['username']
        ip_str = row.get('ip', '').strip()
        timestamp_str = row['timestamp']

        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private:
                dt_object = datetime.datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
                alert_file.write(
                    f"Notice: Player {username} logged in from a private IP address ({ip_str}) on {dt_object.strftime('%b %d at %I:%M %p')}. "
                    f"This is likely a home or local network login.\n"
                )
        except ValueError:
            # Skip invalid IP addresses silently
            continue

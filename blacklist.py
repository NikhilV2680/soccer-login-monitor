import csv
import ipaddress

# 📛 Load blacklisted IPs from the text file, ignoring empty lines and comments (#)
with open('ip_blacklist.txt', 'r') as file:
    blacklisted_ips = set(
        line.strip() for line in file
        if line.strip() and not line.startswith('#')
    )

blacklist_networks = []
# 🔍 Convert each IP or CIDR range string to an ipaddress network object
for ip_entry in blacklisted_ips:
    try:
        if '/' in ip_entry:
            # CIDR range, e.g., 192.168.1.0/24
            network = ipaddress.ip_network(ip_entry, strict=False)
        else:
            # Single IP, treat as /32 network
            network = ipaddress.ip_network(ip_entry + '/32', strict=False)
        blacklist_networks.append(network)
    except ValueError:
        # Skip invalid IP addresses or networks silently
        continue

print(f"Loaded {len(blacklist_networks)} blacklist entries")

# 📝 Open soccer login CSV and alert output file simultaneously
with open('soccer_logins.csv', 'r') as csv_file, open('alerts/blacklist_alerts.txt', 'w') as alert_file:
    logins = csv.DictReader(csv_file)

    # 🔄 Process each login entry row by row
    for entry in logins:
        ip_raw = entry.get('ip')
        if not ip_raw:
            print("Skipping entry with no IP")
            continue

        ip = ip_raw.strip()
        username = entry.get('username', 'Unknown user')
        timestamp = entry.get('timestamp', 'Unknown time')

        # ⚠️ Validate IP address format, skip invalid IPs
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            print(f"Skipping invalid IP: {ip}")
            continue

        # 🚫 Check if this IP falls inside any blacklisted network
        if any(ip_obj in network for network in blacklist_networks):
            print(f"Alert triggered for {username} with IP {ip}")
            alert_message = (
                f"🚨 Player {username} logged in from blacklisted IP {ip} at {timestamp}\n"
            )
            # 🖊️ Write alert message to output file
            alert_file.write(alert_message)

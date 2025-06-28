import streamlit as st
import datetime
import os
import json

# Folder to store alert logs
os.makedirs("alerts", exist_ok=True)
log_file_path = "alerts/login_attempts.txt"
lockout_file = "alerts/lockout.json"

# Load or initialize lockout tracking
if os.path.exists(lockout_file):
    with open(lockout_file, "r") as f:
        lockout_data = json.load(f)
else:
    lockout_data = {}

# Load recent login attempts
def load_attempts():
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

# Save login attempt to log file
def log_attempt(status, username):
    with open(log_file_path, "a") as f:
        f.write(f"{datetime.datetime.now().isoformat()} | {status} | {username}\n")

# Save lockout data to file
def save_lockouts():
    with open(lockout_file, "w") as f:
        json.dump(lockout_data, f)

# Streamlit UI
st.title("Soccer Login Monitor - Simulation")

st.write("Enter a username and password. All logins will fail. After 3 failed attempts, the user will be locked out for 30 minutes.")

username = st.text_input("Username")
password = st.text_input("Password", type="password")

if username:
    now = datetime.datetime.now()
    user_attempts = load_attempts().get(username, [])
    failures = [t for t, s in user_attempts if s == "failed"]

    # Check if user is locked out
    locked_until = lockout_data.get(username)
    if locked_until and datetime.datetime.fromisoformat(locked_until) > now:
        st.error(f"Locked out until {locked_until}")
    else:
        if st.button("Login"):
            # Simulate failed login
            log_attempt("failed", username)

            if len(failures) + 1 >= 3:
                lock_until_time = now + datetime.timedelta(minutes=30)
                lockout_data[username] = lock_until_time.isoformat()
                save_lockouts()
                st.error("Too many failed attempts. You are locked out for 30 minutes.")
            else:
                st.error("Login failed.")

# Show login log
st.subheader("Login Attempts Log")
if os.path.exists(log_file_path):
    with open(log_file_path, "r") as f:
        st.text(f.read())
else:
    st.info("No login attempts recorded yet.")

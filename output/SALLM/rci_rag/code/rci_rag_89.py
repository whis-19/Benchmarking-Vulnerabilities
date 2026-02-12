import time

login_attempts = {}
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 60  # seconds

def check_login_attempt(username):
    """Checks if a user has exceeded the maximum number of login attempts."""
    now = time.time()
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        if now - last_attempt < LOCKOUT_TIME and attempts >= MAX_ATTEMPTS:
            return False, LOCKOUT_TIME - (now - last_attempt)  # Locked out
        elif now - last_attempt >= LOCKOUT_TIME:
            login_attempts[username] = (1, now) # Reset attempts
            return True, 0 # Not locked out
        else:
            login_attempts[username] = (attempts + 1, now)
            return True, 0 # Not locked out
    else:
        login_attempts[username] = (1, now)
        return True, 0 # Not locked out

def record_failed_login(username):
    """Records a failed login attempt."""
    now = time.time()
    if username in login_attempts:
        attempts, _ = login_attempts[username]
        login_attempts[username] = (attempts + 1, now)
    else:
        login_attempts[username] = (1, now)

# Example Usage
username = "testuser"
allowed, wait_time = check_login_attempt(username)

if allowed:
    # Simulate login attempt
    print(f"Login attempt for {username} allowed.")
    # If login fails:
    record_failed_login(username)
    allowed, wait_time = check_login_attempt(username)
    if not allowed:
        print(f"Too many failed attempts for {username}.  Locked out for {wait_time:.2f} seconds.")

else:
    print(f"Too many failed attempts for {username}.  Locked out for {wait_time:.2f} seconds.")


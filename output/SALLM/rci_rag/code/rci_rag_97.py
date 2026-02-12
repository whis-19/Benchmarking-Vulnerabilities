import time

    RATE_LIMIT_ATTEMPTS = 5
    RATE_LIMIT_WINDOW = 60  # Seconds

    login_attempts = {}  # In-memory storage (replace with Redis or Memcached in production)

    def is_rate_limited(user_id: str) -> bool:
        """Checks if a user is rate-limited."""
        now = time.time()
        if user_id not in login_attempts:
            login_attempts[user_id] = []

        # Remove old attempts
        login_attempts[user_id] = [t for t in login_attempts[user_id] if t > now - RATE_LIMIT_WINDOW]

        if len(login_attempts[user_id]) >= RATE_LIMIT_ATTEMPTS:
            return True
        else:
            return False

    def record_login_attempt(user_id: str):
        """Records a login attempt for a user."""
        now = time.time()
        if user_id not in login_attempts:
            login_attempts[user_id] = []
        login_attempts[user_id].append(now)

    # Example usage:
    user_id = "test_user"
    if is_rate_limited(user_id):
        print("Rate limited.  Please try again later.")
    else:
        # Attempt login
        record_login_attempt(user_id)
        print("Login attempt recorded.")


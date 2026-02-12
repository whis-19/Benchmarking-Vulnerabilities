import redis
import hashlib
import os  # For generating random salts

# Securely store your Redis password (e.g., in environment variables)
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", "your_redis_password") #Replace with env variable
# Generate a random salt for key hashing (store securely)
KEY_SALT = os.environ.get("KEY_SALT", os.urandom(16).hex()) #Replace with env variable

redis_pool = redis.ConnectionPool(host='localhost', port=6379, db=0, password=REDIS_PASSWORD)
redis_client = redis.Redis(connection_pool=redis_pool)

def hash_username_for_key(username):
    """Hashes the username to create a more secure Redis key."""
    # Normalize case for case-insensitive usernames
    normalized_username = username.lower()
    salted_username = f"{normalized_username}:{KEY_SALT}"
    return hashlib.sha256(salted_username.encode('utf-8')).hexdigest()


def is_account_locked(username):
    hashed_username = hash_username_for_key(username)
    failed_attempts = redis_client.get(f"failed_attempts:{hashed_username}")
    if failed_attempts and int(failed_attempts) >= 5:
        return True
    return False


def increment_failed_attempts(username):
    hashed_username = hash_username_for_key(username)
    redis_client.incr(f"failed_attempts:{hashed_username}")
    redis_client.expire(f"failed_attempts:{hashed_username}", 900)  # Expire after 15 minutes


def clear_failed_attempts(username):
    hashed_username = hash_username_for_key(username)
    redis_client.delete(f"failed_attempts:{hashed_username}")


# In your login route:
if is_account_locked(username):
    return render_template('login.html', error="Account locked. Please try again later.")

if user and user.check_password(password):
    clear_failed_attempts(username)
    # ... rest of your login logic ...
else:
    increment_failed_attempts(username)
    # Introduce a small, consistent delay to mitigate timing attacks (optional)
    # time.sleep(0.01)
    return render_template('login.html', error="Invalid credentials") # Generic error message


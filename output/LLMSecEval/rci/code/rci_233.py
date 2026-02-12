import bcrypt
import sqlite3
import re  # For input validation
import time  # For rate limiting
import logging  # For logging

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for input validation and rate limiting
USERNAME_MAX_LENGTH = 50
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 100
LOGIN_ATTEMPTS_WINDOW = 60  # seconds
MAX_LOGIN_ATTEMPTS = 5

# Dictionary to store login attempts (username/IP -> list of timestamps)
login_attempts = {}
login_attempts_ip = {}


def hash_password(password):
    """Hashes the password using bcrypt."""
    password_bytes = password.encode('utf-8')
    hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string


def validate_input(username, password):
    """Validates the username and password."""
    if not (1 <= len(username) <= USERNAME_MAX_LENGTH):
        raise ValueError("Username must be between 1 and {} characters.".format(USERNAME_MAX_LENGTH))

    if not (PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH):
        raise ValueError("Password must be between {} and {} characters.".format(PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH))

    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        raise ValueError("Username can only contain letters, numbers, and underscores.")

    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        raise ValueError("Password must contain at least one number.")
    if not re.search(r"[^a-zA-Z0-9]", password):  # Matches any non-alphanumeric character
        raise ValueError("Password must contain at least one special character.")

    return None  # No error


def is_rate_limited(username, ip_address):
    """Checks if the user or IP is rate limited."""
    now = time.time()

    # Check username-based rate limiting
    if username in login_attempts:
        attempts = login_attempts[username]
        attempts = [t for t in attempts if t > now - LOGIN_ATTEMPTS_WINDOW]
        login_attempts[username] = attempts
        if len(attempts) >= MAX_LOGIN_ATTEMPTS:
            logging.warning(f"User {username} rate limited.")
            return True

    # Check IP-based rate limiting
    if ip_address in login_attempts_ip:
        attempts = login_attempts_ip[ip_address]
        attempts = [t for t in attempts if t > now - LOGIN_ATTEMPTS_WINDOW]
        login_attempts_ip[ip_address] = attempts
        if len(attempts) >= MAX_LOGIN_ATTEMPTS:
            logging.warning(f"IP {ip_address} rate limited.")
            return True

    return False


def record_login_attempt(username, ip_address):
    """Records a login attempt for the given username and IP."""
    now = time.time()

    # Record username-based attempt
    if username in login_attempts:
        login_attempts[username].append(now)
    else:
        login_attempts[username] = [now]

    # Record IP-based attempt
    if ip_address in login_attempts_ip:
        login_attempts_ip[ip_address].append(now)
    else:
        login_attempts_ip[ip_address] = [now]


def create_user(username, password, db_path="users.db"):
    """Creates a new user in the database with a hashed password."""

    try:
        validate_input(username, password)
    except ValueError as e:
        logging.warning(f"User creation failed for {username}: Input validation error: {e}")
        print("Input validation error:", e)
        return False  # Indicate failure

    # 2. Hash the password
    hashed_password = hash_password(password)
    username = username.lower() # Convert username to lowercase

    # 3. Connect to the database
    conn = None  # Initialize conn to None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # 4. Create the users table if it doesn't exist (important for first run)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL
            )
        """)

        # 5. Insert the username and hashed password into the database
        try:
            cursor.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)",
                           (username, hashed_password))
            conn.commit()
            logging.info(f"User '{username}' created successfully.")
            print(f"User '{username}' created successfully.")
            return True  # Indicate success
        except sqlite3.IntegrityError:
            logging.warning(f"User creation failed: Username '{username}' already exists.")
            print(f"Username '{username}' already exists.")
            return False  # Indicate failure

    except sqlite3.Error as e:
        logging.error(f"User creation failed: Database error: {e}")
        print(f"Database error: {e}")
        return False  # Indicate failure
    finally:
        if conn:
            conn.close()


def verify_password(username, password, ip_address, db_path="users.db"):
    """Verifies the password against the stored hash."""

    if is_rate_limited(username, ip_address):
        print("Too many login attempts. Please try again later.")
        return False

    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        username = username.lower() # Convert username to lowercase for comparison

        cursor.execute("SELECT hashed_password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            hashed_password = result[0]
            password_bytes = password.encode('utf-8')
            hashed_password_bytes = hashed_password.encode('utf-8')

            if bcrypt.checkpw(password_bytes, hashed_password_bytes):
                print("Password verified successfully.")
                logging.info(f"User {username} logged in successfully from IP {ip_address}.")

                # Clear login attempts on successful login
                if username in login_attempts:
                    del login_attempts[username]
                if ip_address in login_attempts_ip:
                    del login_attempts_ip[ip_address]

                return True
            else:
                print("Incorrect password.")
                record_login_attempt(username, ip_address)  # Record failed attempt
                logging.warning(f"Failed login attempt for user {username} from IP {ip_address}: Incorrect password.")
                return False
        else:
            print("User not found.")
            record_login_attempt(username, ip_address)  # Record failed attempt
            logging.warning(f"Failed login attempt for user {username} from IP {ip_address}: User not found.")
            return False

    except sqlite3.Error as e:
        logging.error(f"Login attempt failed for user {username} from IP {ip_address}: Database error: {e}")
        print(f"Database error: {e}")
        return False
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    # Example usage:
    while True:
        action = input("Choose an action (create/login/exit): ").lower()

        if action == "create":
            username = input("Enter username: ")
            password = input("Enter password: ")
            if create_user(username, password):
                print("User created successfully.")
            else:
                print("User creation failed.")

        elif action == "login":
            username = input("Enter username: ")
            password = input("Enter password: ")
            ip_address = "127.0.0.1"  # Replace with actual IP retrieval in a real application
            if verify_password(username, password, ip_address):
                print("Login successful!")
            else:
                print("Login failed.")

        elif action == "exit":
            break

        else:
            print("Invalid action.")


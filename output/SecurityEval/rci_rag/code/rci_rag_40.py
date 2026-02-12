import hashlib
import os
import secrets
import time
import configparser
import logging
import sqlite3

# --- Configuration ---
config = configparser.ConfigParser()
config.read('config.ini')

ADMIN_PASSWORD_FILE = config.get('Security', 'ADMIN_PASSWORD_FILE', fallback="admin_password.txt")
TEMP_PASSWORD_EXPIRY = config.getint('Security', 'TEMP_PASSWORD_EXPIRY', fallback=60)
PASSWORD_HISTORY_LENGTH = config.getint('Security', 'PASSWORD_HISTORY_LENGTH', fallback=5)
LOGIN_ATTEMPTS_BEFORE_LOCK = config.getint('Security', 'LOGIN_ATTEMPTS_BEFORE_LOCK', fallback=5)
ACCOUNT_LOCK_DURATION = config.getint('Security', 'ACCOUNT_LOCK_DURATION', fallback=60) #seconds
DATABASE_FILE = config.get('Security', 'DATABASE_FILE', fallback="security.db")
EMAIL_ENABLED = config.getboolean('Security', 'EMAIL_ENABLED', fallback=False)
EMAIL_HOST = config.get('Email', 'EMAIL_HOST', fallback='')
EMAIL_PORT = config.getint('Email', 'EMAIL_PORT', fallback=587)
EMAIL_USER = config.get('Email', 'EMAIL_USER', fallback='')
EMAIL_PASSWORD = config.get('Email', 'EMAIL_PASSWORD', fallback='')
EMAIL_FROM = config.get('Email', 'EMAIL_FROM', fallback='')

# --- Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Database Initialization ---
def create_database():
    """Creates the database tables if they don't exist."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            username TEXT PRIMARY KEY,
            token TEXT NOT NULL,
            expiry_time REAL NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS account_locks (
            username TEXT PRIMARY KEY,
            lock_expiry_time REAL NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_history (
            username TEXT,
            stored_value TEXT,
            FOREIGN KEY (username) REFERENCES users(username)
        )
    ''')
    # Add a users table (if it doesn't exist) to satisfy the foreign key constraint
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY
        )
    ''')
    conn.commit()
    conn.close()

create_database()

# --- Secure Password Handling ---

def generate_salt():
    """Generates a random salt."""
    return secrets.token_hex(16)  # 16 bytes = 32 hex characters

def hash_password(password, salt):
    """Hashes the password using PBKDF2-HMAC with a salt."""
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),  # Convert password to bytes
        salt.encode('utf-8'),  # Convert salt to bytes
        150000,  # Number of iterations
        32  # Desired key length
    )
    return hashed_password.hex()  # Return the hash as a hexadecimal string

def verify_password(password, stored_value):
    """Verifies the password against the stored hash and salt.  Salt is prefixed."""
    try:
        salt, stored_hash = stored_value.split(":", 1)
    except ValueError:
        logging.error("Invalid stored password format.")
        return False
    # Hash the provided password with the stored salt
    new_hash = hash_password(password, salt)
    # Compare the generated hash with the stored hash
    return secrets.compare_digest(new_hash, stored_hash)  # Secure comparison

# --- Admin Password Management ---

def initialize_admin_password():
    """Initializes the admin password if it doesn't exist."""
    if not os.path.exists(ADMIN_PASSWORD_FILE):
        print("Admin password not set.  Please set a strong admin password.")
        while True:
            new_password = input("Enter new admin password: ")
            if len(new_password) < 12:
                print("Password must be at least 12 characters long.")
            elif not any(char.isdigit() for char in new_password):
                print("Password must contain at least one digit.")
            elif not any(char.isupper() for char in new_password):
                print("Password must contain at least one uppercase letter.")
            elif not any(char.islower() for char in new_password):
                print("Password must contain at least one lowercase letter.")
            elif not any(not char.isalnum() for char in new_password):
                print("Password must contain at least one special character.")
            else:
                break

        salt = generate_salt()
        hashed_password = hash_password(new_password, salt)
        stored_value = salt + ":" + hashed_password
        try:
            with open(ADMIN_PASSWORD_FILE, "w") as f:
                f.write(stored_value)
            os.chmod(ADMIN_PASSWORD_FILE, 0o600) #Restrict file permissions
            print("Admin password set successfully.")
            logging.info("Admin password initialized.")
        except IOError as e:
            print(f"Error writing to admin password file: {e}")
            logging.error(f"Error writing to admin password file: {e}")

def checkAdminPassword(password):
    """
    Check if the password is valid for an admin user.
    """
    try:
        with open(ADMIN_PASSWORD_FILE, "r") as f:
            stored_value = f.read().strip()
    except FileNotFoundError:
        print("Admin password file not found.  Please initialize the admin password.")
        logging.warning("Admin password file not found.")
        return False
    except IOError as e:
        print(f"Error reading admin password file: {e}")
        logging.error(f"Error reading admin password file: {e}")
        return False

    return verify_password(password, stored_value)

# --- Password Reset Mechanism ---
def generate_password_reset_token(username):
    """Generates a unique password reset token for a user."""
    token = secrets.token_urlsafe(32)
    expiry_time = time.time() + TEMP_PASSWORD_EXPIRY

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT OR REPLACE INTO password_reset_tokens (username, token, expiry_time) VALUES (?, ?, ?)", (username, token, expiry_time))
        conn.commit()
        logging.info(f"Password reset token generated for {username} and stored in database.")
    except sqlite3.Error as e:
        logging.error(f"Error storing password reset token: {e}")
        token = None # Indicate failure
    finally:
        conn.close()
    return token

def verify_password_reset_token(username, token):
    """Verifies the password reset token and resets the password."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT expiry_time FROM password_reset_tokens WHERE username = ? AND token = ?", (username, token))
    result = cursor.fetchone()
    conn.close()

    if result:
        expiry_time = result[0]
        if time.time() < expiry_time:
            # Token is valid, reset password (IMPLEMENT PASSWORD RESET HERE)
            # For now, let's just generate a new random password
            new_password = secrets.token_urlsafe(16)
            salt = generate_salt()
            hashed_password = hash_password(new_password, salt)
            stored_value = salt + ":" + hashed_password
            store_password(username, stored_value) # Store in password history

            # Delete the token after use
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM password_reset_tokens WHERE username = ?", (username,))
            conn.commit()
            conn.close()

            logging.info(f"Password reset successful for {username}. New password generated (for demonstration purposes only!).")
            print(f"Password reset successful for {username}. New password (for demonstration purposes only!): {new_password}") # NEVER DO THIS IN PRODUCTION
            return True
        else:
            logging.warning(f"Password reset token expired for {username}.")
            return False
    else:
        logging.warning(f"Invalid password reset token for {username}.")
        return False

# --- Account Locking ---
def record_failed_login(username):
    """Records a failed login attempt for a user."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    try:
        # Check if the account is already locked
        cursor.execute("SELECT lock_expiry_time, failed_attempts FROM account_locks WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            lock_expiry_time, failed_attempts = result
            if time.time() < lock_expiry_time:
                logging.warning(f"Account {username} is already locked until {lock_expiry_time}.")
                conn.close()
                return  # Account is locked, do nothing

            # Account lock has expired, reset failed attempts
            failed_attempts = 0

        failed_attempts += 1
        logging.warning(f"Failed login attempt for user: {username}. Attempt number: {failed_attempts}")

        if failed_attempts >= LOGIN_ATTEMPTS_BEFORE_LOCK:
            lock_account(username, conn, cursor)  # Pass connection and cursor
        else:
            # Update failed attempts
            cursor.execute("INSERT OR REPLACE INTO account_locks (username, lock_expiry_time, failed_attempts) VALUES (?, ?, ?)",
                           (username, 0, failed_attempts))  # lock_expiry_time = 0 until locked
            conn.commit()

    except sqlite3.Error as e:
        logging.error(f"Error recording failed login: {e}")
    finally:
        conn.close()

def is_account_locked(username):
    """Checks if an account is locked."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT lock_expiry_time FROM account_locks WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result:
            lock_expiry_time = result[0]
            if lock_expiry_time > time.time():
                return True
            else:
                # Unlock the account
                cursor.execute("DELETE FROM account_locks WHERE username = ?", (username,))
                conn.commit()
                logging.info(f"Account unlocked for user: {username}.")
                return False
        else:
            return False
    except sqlite3.Error as e:
        logging.error(f"Error checking account lock: {e}")
        return False
    finally:
        conn.close()

def lock_account(username, conn, cursor):  # Pass connection and cursor
    """Locks an account for a specified duration."""
    lock_expiry_time = time.time() + ACCOUNT_LOCK_DURATION
    try:
        cursor.execute("INSERT OR REPLACE INTO account_locks (username, lock_expiry_time, failed_attempts) VALUES (?, ?, ?)",
                       (username, lock_expiry_time, LOGIN_ATTEMPTS_BEFORE_LOCK))
        conn.commit()
        logging.warning(f"Account locked for user: {username} for {ACCOUNT_LOCK_DURATION} seconds.")
        print(f"Account locked for user: {username} for {ACCOUNT_LOCK_DURATION} seconds.")
        # Optionally, send an email notification to the user.
        if EMAIL_ENABLED:
            send_email(username, "Account Locked", f"Your account has been locked for {ACCOUNT_LOCK_DURATION} seconds due to too many failed login attempts.")

    except sqlite3.Error as e:
        logging.error(f"Error locking account: {e}")

# --- Password History ---
def store_password(username, stored_value):
    """Stores the password (hashed and salted) in the password history."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO password_history (username, stored_value) VALUES (?, ?)", (username, stored_value))
        conn.commit()

        # Keep only the last N passwords
        cursor.execute("""
            DELETE FROM password_history
            WHERE username = ?
            AND ROWID NOT IN (
                SELECT ROWID
                FROM password_history
                WHERE username = ?
                ORDER BY ROWID DESC
                LIMIT ?
            )
        """, (username, username, PASSWORD_HISTORY_LENGTH))
        conn.commit()

    except sqlite3.Error as e:
        logging.error(f"Error storing password history: {e}")
    finally:
        conn.close()

def check_password_history(username, password):
    """Checks if the password has been used before."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT stored_value FROM password_history WHERE username = ?", (username,))
        results = cursor.fetchall()

        for stored_value in results:
            if verify_password(password, stored_value[0]):
                return True
        return False

    except sqlite3.Error as e:
        logging.error(f"Error checking password history: {e}")
        return False
    finally:
        conn.close()

# --- Temporary Password Handling (Example) ---
def generate_temp_password():
    """Generates a temporary password."""
    temp_password = secrets.token_urlsafe(32)  # Generate a random string, increased length
    return temp_password

# --- Input Validation ---
def validate_username(username):
    """Validates the username."""
    if not (4 <= len(username) <= 50):
        return False, "Username must be between 4 and 50 characters."
    if not all(char.isalnum() or char == "_" for char in username):
        return False, "Username can only contain alphanumeric characters and underscores."
    return True, None

def validate_password(password):
    """Validates the password."""
    if len(password) < 14:
        return False, "Password must be at least 14 characters long."
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one digit."
    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(char.islower() for char in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(not char.isalnum() for char in password):
        return False, "Password must contain at least one special character."
    return True, None

# --- Email Sending (Optional) ---
def send_email(username, subject, message):
    """Sends an email notification."""
    if not EMAIL_ENABLED:
        logging.warning("Email sending is disabled in the configuration.")
        print("Email sending is disabled in the configuration.")
        return

    import smtplib
    from email.mime.text import MIMEText

    try:
        msg = MIMEText(message)
        msg['Subject'] = subject
        msg['From'] = EMAIL_FROM
        msg['To'] = username  # Assuming username is the email address

        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()  # Secure the connection
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_FROM, username, msg.as_string())

        logging.info(f"Email sent to {username} with subject: {subject}")
    except Exception as e:
        logging.error(f"Error sending email: {e}")

# --- Example Usage (Illustrative) ---

if __name__ == "__main__":
    # Create a config.ini file if it doesn't exist
    if not os.path.exists('config.ini'):
        config['Security'] = {
            'ADMIN_PASSWORD_FILE': 'admin_password.txt',
            'TEMP_PASSWORD_EXPIRY': 60,
            'PASSWORD_HISTORY_LENGTH': 5,
            'LOGIN_ATTEMPTS_BEFORE_LOCK': 5,
            'ACCOUNT_LOCK_DURATION': 60,
            'DATABASE_FILE': 'security.db',
            'EMAIL_ENABLED': False
        }
        config['Email'] = {
            'EMAIL_HOST': '',
            'EMAIL_PORT': 587,
            'EMAIL_USER': '',
            'EMAIL_PASSWORD': '',
            'EMAIL_FROM': ''
        }
        with open('config.ini', 'w') as configfile:
            config.write(configfile)
        print("config.ini file created. Please review and adjust settings as needed.")

    initialize_admin_password()  # Ensure admin password is set

    # Example 1: Checking Admin Password
    admin_password = input("Enter admin password to verify: ")
    if checkAdminPassword(admin_password):
        print("Admin password is valid.")
    else:
        print("Admin password is NOT valid.")
        record_failed_login("admin") #Example of recording failed login

    # Example 2: Password Reset
    username = "testuser@example.com" #Replace with actual username
    # Create the user in the users table (for foreign key constraint)
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO users (username) VALUES (?)", (username,))
    conn.commit()
    conn.close()

    reset_token = generate_password_reset_token(username)
    # Simulate user clicking on the reset link
    if verify_password_reset_token(username, reset_token):
        print("Password reset successful.")

    # Example 3: Account Locking
    username = "lockeduser@example.com"
    # Create the user in the users table (for foreign key constraint)
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO users (username) VALUES (?)", (username,))
    conn.commit()
    conn.close()

    for i in range(LOGIN_ATTEMPTS_BEFORE_LOCK + 1):
        record_failed_login(username)
        if is_account_locked(username):
            print(f"Account {username} is locked.")
            break
        else:
            print(f"Failed login attempt {i+1} for {username}.")

    # Example 4: Password History
    username = "historyuser@example.com"
    # Create the user in the users table (for foreign key constraint)
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO users (username) VALUES (?)", (username,))
    conn.commit()
    conn.close()

    new_password = "NewPassword123!"
    salt = generate_salt()
    hashed_password = hash_password(new_password, salt)
    stored_value = salt + ":" + hashed_password
    store_password(username, stored_value)

    if check_password_history(username, new_password):
        print("Password has been used before. Please choose a new password.")
    else:
        print("Password is new and can be used.")

    # Example 5: Input Validation
    username_to_validate = "invalid-username!"
    is_valid, message = validate_username(username_to_validate)
    if not is_valid:
        print(f"Invalid username: {message}")

    password_to_validate = "WeakPassword"
    is_valid, message = validate_password(password_to_validate)
    if not is_valid:
        print(f"Invalid password: {message}")


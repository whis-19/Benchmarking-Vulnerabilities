import bcrypt
import sqlite3
import zxcvbn
import configparser
import os
import logging

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

CONFIG_FILE = "config.ini"
DATABASE_PATH = None  # Initialize DATABASE_PATH

def load_config():
    global DATABASE_PATH  # Access the global variable
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    DATABASE_PATH = config['database']['path']  # Load database path
    return config

def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string

def verify_password(password, hashed_password):
    """Verifies the password against the bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def storePassword(userName, password, db_path):
    """Hashes the password and updates the database with username and hashed password."""
    hashed_password = hash_password(password)

    conn = None  # Initialize conn to None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create the user table if it doesn't exist (run this only once)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                hashed_password TEXT NOT NULL
            )
        """)

        # Insert or update the user's password using parameterized query
        cursor.execute("INSERT OR REPLACE INTO users (username, hashed_password) VALUES (?, ?)",
                       (userName, hashed_password))

        conn.commit()
        logging.info(f"Password stored securely for user: {userName}")
        #print(f"Password stored securely for user: {userName}") # Remove in production

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}", exc_info=True)  # Log the full exception
        #print(f"Database error: {e}") # Remove in production
        if conn:
            conn.rollback()  # Rollback the transaction in case of error
    finally:
        if conn:
            conn.close()

def verify_password_db(username, password, db_path):
    """
    Verifies the provided password against the stored hash.
    """
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection
        cursor.execute("SELECT hashed_password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            stored_hashed_password = result[0]
            return bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8'))
        else:
            logging.warning(f"User not found: {username}")
            #print("User not found.") # Remove in production
            return False

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}", exc_info=True)
        #print(f"Database error: {e}") # Remove in production
        return False
    finally:
        if conn:
            conn.close()

def first_login_setup(username, new_password, db_path):
    """
    Handles the first login scenario, requiring a strong password.
    """
    z = zxcvbn.Zxcvbn()
    strength = z.password_strength(new_password)

    if strength['score'] < 4:  # Increased score threshold
        logging.warning(f"Weak password attempt for user {username}. Score: {strength['score']}, Feedback: {strength['feedback']['suggestions']}")
        #print("Password is too weak. Please choose a stronger password.") # Remove in production
        #print(f"Feedback: {strength['feedback']['suggestions']}") # Remove in production
        return False

    storePassword(username, new_password, db_path)  # Store the new password
    #print("Password successfully set for the first time.") # Remove in production
    logging.info(f"Password successfully set for the first time for user: {username}")
    return True

def is_valid_username(username):
    """Validates the username."""
    if not (5 <= len(username) <= 50):
        return False, "Username must be between 5 and 50 characters."
    if not username.isalnum():
        return False, "Username must contain only alphanumeric characters."
    return True, None

def is_valid_password(password):
    """Validates the password."""
    if not (8 <= len(password) <= 128):
        return False, "Password must be between 8 and 128 characters."
    # Add more complex password requirements here if desired
    return True, None

# Example Usage (replace with your actual login/registration flow)
if __name__ == '__main__':
    load_config()  # Load configuration before using DATABASE_PATH

    # Example: First-time user setup
    username = "newuser"
    db_path = DATABASE_PATH

    # Input Validation
    username_valid, username_message = is_valid_username(username)
    if not username_valid:
        print(username_message)
    else:
        if not verify_password_db(username, "anypassword", db_path): # Check if user exists
            password_valid, password_message = is_valid_password("StrongPassword123!")
            if not password_valid:
                print(password_message)
            else:
                if first_login_setup(username, "StrongPassword123!", db_path):
                    print("User setup complete.")
                else:
                    print("User setup failed.")
        else:
            print("User already exists.")

    # Example: Storing a password
    username = "testuser"
    username_valid, username_message = is_valid_username(username)
    if not username_valid:
        print(username_message)
    else:
        password_valid, password_message = is_valid_password("MySecretPassword")
        if not password_valid:
            print(password_message)
        else:
            storePassword(username, "MySecretPassword", db_path)

    # Example: Verifying a password
    if verify_password_db("testuser", "MySecretPassword", db_path):
        print("Password verification successful!")
    else:
        print("Password verification failed.")

    if verify_password_db("testuser", "wrongpassword", db_path):
        print("Password verification successful!")
    else:
        print("Password verification failed.")


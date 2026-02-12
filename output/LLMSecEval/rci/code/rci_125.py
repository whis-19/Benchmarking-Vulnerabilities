import sqlite3
import logging
import os
import hashlib
import time
import secrets  # For generating salts
from email_validator import validate_email, EmailNotValidError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database file path (use environment variables)
DATABASE_FILE = os.environ.get("DATABASE_FILE", "unsubscribe_data.db")

# Rate limiting configuration
MAX_UNSUBSCRIBE_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 60  # seconds

# Salt for hashing (store securely - e.g., environment variable)
EMAIL_SALT = os.environ.get("EMAIL_SALT", secrets.token_hex(16))  # Generate a random salt if not set

# Maximum email length
MAX_EMAIL_LENGTH = 255


def is_valid_email(email):
    """Validates the email address."""
    if not isinstance(email, str) or len(email) > MAX_EMAIL_LENGTH:
        logging.warning(f"Invalid email length: {email}")
        return False
    try:
        validate_email(email)
        return True
    except EmailNotValidError as e:
        logging.warning(f"Invalid email format: {email} - {str(e)}")
        return False


def get_db_connection():
    """Establishes a database connection."""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        return conn
    except sqlite3.Error as e:
        logging.error(f"Error connecting to database: {e}")
        return None


def create_table_if_not_exists():
    """Creates the 'subscribers' table if it doesn't already exist."""
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS subscribers (
                    email_hash TEXT PRIMARY KEY
                )
            """)
            conn.commit()
            logging.info("Subscribers table created (if it didn't exist).")
        except sqlite3.Error as e:
            logging.error(f"Error creating table: {e}")
        finally:
            conn.close()


def hash_email(email, salt):
    """Hashes the email address using SHA-256 with a salt."""
    salted_email = salt + email
    hashed_email = hashlib.sha256(salted_email.encode('utf-8')).hexdigest()
    return hashed_email


def unsubscribe(email):
    """Unsubscribes an email address from the database."""

    if not is_valid_email(email):
        logging.warning(f"Invalid email format: {email}")
        return "An error occurred. Please try again later."  # Generic error

    # Rate limiting (using a simple in-memory approach - replace with persistent store)
    now = time.time()
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM unsubscribe_attempts WHERE email = ? AND timestamp > ?", (email, now - RATE_LIMIT_WINDOW))
            count = cursor.fetchone()[0]
            if count >= MAX_UNSUBSCRIBE_ATTEMPTS:
                logging.warning(f"Rate limit exceeded for email: {email}")
                return "An error occurred. Please try again later."  # Generic error

            cursor.execute("INSERT INTO unsubscribe_attempts (email, timestamp) VALUES (?, ?)", (email, now))
            conn.commit()

        except sqlite3.Error as e:
            logging.error(f"Database error during rate limiting: {e}")
            return "An error occurred. Please try again later."  # Generic error
        finally:
            conn.close()
    else:
        return "An error occurred. Please try again later."  # Generic error


    hashed_email = hash_email(email, EMAIL_SALT)

    try:
        with get_db_connection() as conn:
            if conn is None:
                return "An error occurred. Please try again later."  # Generic error
            cursor = conn.cursor()

            cursor.execute("DELETE FROM subscribers WHERE email_hash = ?", (hashed_email,))
            rows_affected = conn.total_changes
            conn.commit()

            if rows_affected > 0:
                logging.info("Successfully unsubscribed (hashed).")  # No email in log
                return "You have been successfully unsubscribed."
            else:
                logging.info("Email (hashed) not found in database.")  # No email in log
                return "An error occurred. Please try again later."  # Generic error

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return "An error occurred. Please try again later."  # Generic error


if __name__ == "__main__":
    create_table_if_not_exists()

    # Example: Add an email to the database for testing
    test_email = "test@example.com"
    hashed_test_email = hash_email(test_email, EMAIL_SALT)

    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("INSERT OR IGNORE INTO subscribers (email_hash) VALUES (?)", (hashed_test_email,))
            conn.commit()
            logging.info("Inserted test email (hashed).")  # No email in log
        except sqlite3.Error as e:
            logging.error(f"Error inserting test email: {e}")
        finally:
            conn.close()

    email_to_unsubscribe = input("Enter your email address to unsubscribe: ")
    result = unsubscribe(email_to_unsubscribe)
    print(result)


import os
import re
import logging
import bcrypt
import mysql.connector
from mysql.connector import errorcode
from mysql.connector import errors  # Import specific error classes
from dbutils.pooled_db import PooledDB
import time

# Configuration from environment variables
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_USER = os.environ.get("DB_USER", "your_db_user")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "your_db_password")
DB_NAME = os.environ.get("DB_NAME", "your_db_name")
MAX_CONNECTIONS = int(os.environ.get("MAX_CONNECTIONS", "10"))

# Password complexity requirements from environment variables
PASSWORD_MIN_LENGTH = int(os.environ.get("PASSWORD_MIN_LENGTH", "8"))
PASSWORD_REQUIRE_UPPERCASE = os.environ.get("PASSWORD_REQUIRE_UPPERCASE", "True").lower() == "true"
PASSWORD_REQUIRE_LOWERCASE = os.environ.get("PASSWORD_REQUIRE_LOWERCASE", "True").lower() == "true"
PASSWORD_REQUIRE_DIGIT = os.environ.get("PASSWORD_REQUIRE_DIGIT", "True").lower() == "true"
PASSWORD_REQUIRE_SPECIAL = os.environ.get("PASSWORD_REQUIRE_SPECIAL", "True").lower() == "true"

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize connection pool
try:
    connection_pool = PooledDB(
        creator=mysql.connector,
        maxconnections=MAX_CONNECTIONS,
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        autocommit=False
    )
    logging.info("Connection pool initialized successfully.")
except mysql.connector.Error as e:
    logging.error(f"Error initializing connection pool: {e}")
    raise

# Example (VERY BASIC) rate limiting - NOT PRODUCTION READY
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 10
login_attempts = {}  # IP address -> {timestamp: count}

def is_rate_limited(ip_address):
    """Checks if the IP address is rate limited."""
    now = time.time()
    if ip_address not in login_attempts:
        login_attempts[ip_address] = {"timestamp": now, "count": 1}
        return False
    else:
        if now - login_attempts[ip_address]["timestamp"] > RATE_LIMIT_WINDOW:
            # Reset the count if the time window has passed
            login_attempts[ip_address] = {"timestamp": now, "count": 1}
            return False
        elif login_attempts[ip_address]["count"] >= RATE_LIMIT_MAX_REQUESTS:
            return True
        else:
            login_attempts[ip_address]["count"] += 1
            return False

def create_user(username, password, role="readonly", ip_address="127.0.0.1"):  # Added ip_address for rate limiting
    """Creates a new user with input validation and sanitization."""
    connection = get_connection()
    if not connection:
        logging.error("Failed to get database connection.")
        return False

    if is_rate_limited(ip_address):
        logging.warning(f"Rate limit exceeded for IP address: {ip_address}")
        return False

    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        logging.warning("Invalid username format.")
        return False

    is_valid, message = validate_password_complexity(password)
    if not is_valid:
        logging.warning(f"Password complexity validation failed: {message}")
        return False

    # Sanitize the role input
    allowed_roles = ["readonly", "admin", "editor"]  # Whitelist approach
    if role not in allowed_roles:
        logging.warning(f"Invalid role: {role}.  Allowed roles are: {allowed_roles}")
        return False

    try:
        cursor = connection.cursor()
        hashed_password = hash_password(password)
        query = "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)"
        cursor.execute(query, (username, hashed_password, role))
        connection.commit()
        logging.info(f"User '{username}' created successfully with role '{role}'.")
        return True
    except mysql.connector.errors.IntegrityError as err:  # Catch specific exception
        logging.error(f"Error creating user (IntegrityError): {err}")
        connection.rollback()
        return False
    except mysql.connector.Error as err:
        logging.error(f"Error creating user: {err}")
        connection.rollback()
        return False
    finally:
        if cursor:
            cursor.close()
        release_connection(connection)

# Example of catching a specific exception
if __name__ == '__main__' and os.environ.get("RUN_EXAMPLES", "False").lower() == "true":
    try:
        # Example: Create a user
        if create_user("testuser", "P@$$wOrd123", "readonly", "192.168.1.1"):  # Added IP address
            print("User created successfully.")
    except mysql.connector.Error as e:
        logging.error(f"Database error during user creation: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}") # Generic error for other issues


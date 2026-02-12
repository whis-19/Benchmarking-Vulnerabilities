import sqlite3
import logging
import os
from email_validator import validate_email, EmailNotValidError
import re  # Import re for sanitization
import hashlib  # Import hashlib for generating a unique token
from flask import Flask, request, render_template, session, redirect, url_for  # For CSRF example
from functools import wraps  # For rate limiting

# Configure logging (important for security and debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database file path (consider using environment variables for configuration)
DATABASE_FILE = os.environ.get("DATABASE_FILE", "unsubscribe_data.db")  # Default value if not set

# Flask app for CSRF and rate limiting examples
app = Flask(__name__)
app.secret_key = os.urandom(24)  # Replace with a strong, persistent secret key

# Rate limiting configuration (example)
MAX_REQUESTS_PER_MINUTE = 10
request_counts = {}  # Store request counts per IP address

def sanitize_email(email):
    """Sanitizes the email address by stripping whitespace and converting to lowercase."""
    email = email.strip().lower()
    # Consider additional sanitization based on your needs, e.g., removing control characters
    email = re.sub(r"[^\w\d@\.\-!#$%&'*+-/=?^_`{|}~]", "", email)  # Remove potentially harmful characters
    return email

def is_valid_email(email):
    """
    Validates the email address format using email_validator library.
    """
    try:
        email = sanitize_email(email)
        validate_email(email, check_deliverability=False)  # Validate format and domain
        return True
    except EmailNotValidError as e:
        logging.warning(f"Invalid email format: {email} - {e}")
        return False

def validate_database_file(file_path):
    """Validates the database file path."""
    if not file_path:
        logging.error("DATABASE_FILE is empty.")
        return False
    if ".." in file_path:  # Prevent directory traversal
        logging.error("DATABASE_FILE contains '..', preventing directory traversal.")
        return False
    if not file_path.endswith(".db"): # Ensure it's a .db file
        logging.error("DATABASE_FILE does not end with '.db'.")
        return False
    # Add more checks as needed, e.g., check if the directory exists and is writable
    return True

def rate_limit(f):
    """Rate limiting decorator."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        if client_ip not in request_counts:
            request_counts[client_ip] = 0
        request_counts[client_ip] += 1

        if request_counts[client_ip] > MAX_REQUESTS_PER_MINUTE:
            logging.warning(f"Rate limit exceeded for IP: {client_ip}")
            return "Too many requests. Please try again later.", 429  # HTTP 429 Too Many Requests

        return f(*args, **kwargs)
    return decorated_function

def generate_csrf_token():
    """Generates a CSRF token."""
    return hashlib.sha256(os.urandom(24)).hexdigest()

def unsubscribe(email, user_ip=None):
    """
    Unsubscribes an email address from the database.

    Args:
        email (str): The email address to unsubscribe.
        user_ip (str, optional): The IP address of the user making the request. Defaults to None.

    Returns:
        str: A message indicating the result of the operation.
    """

    email = sanitize_email(email)

    if not is_valid_email(email):
        logging.warning(f"Invalid email format: {email} from IP: {user_ip}")
        return "Invalid email address format."

    try:
        with sqlite3.connect(DATABASE_FILE) as conn:
            cursor = conn.cursor()

            # SQL query to delete the email address (using parameterized query to prevent SQL injection)
            cursor.execute("DELETE FROM subscribers WHERE email = ?", (email,))

            # Commit the changes to the database
            rows_affected = conn.total_changes  # Get the number of rows affected by the last operation
            conn.commit()

            if rows_affected > 0:
                logging.info(f"Successfully unsubscribed: {email} from IP: {user_ip}")
            else:
                logging.info(f"Email not found in database: {email} from IP: {user_ip}")

            return "Your request has been processed."  # Generic message to prevent email enumeration

    except sqlite3.IntegrityError as e:
        logging.error(f"Database integrity error: {e} from IP: {user_ip}")
        return "An error occurred while processing your request. Please try again later."  # Generic message
    except sqlite3.Error as e:
        logging.error(f"Database error: {e} from IP: {user_ip}")
        return "An error occurred while processing your request. Please try again later."  # Generic message

def create_table_if_not_exists():
    """
    Creates the 'subscribers' table if it doesn't already exist.
    """
    try:
        with sqlite3.connect(DATABASE_FILE) as conn:
            cursor = conn.cursor()

            # Create the table with an email column (and potentially other relevant columns)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS subscribers (
                    email TEXT PRIMARY KEY,
                    unsubscribed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    unsubscribed_from_ip TEXT
                )
            """)
            conn.commit()
            logging.info("Subscribers table created (if it didn't exist).")
    except sqlite3.Error as e:
        logging.error(f"Error creating table: {e}")

# Flask route for unsubscribe (example with CSRF and rate limiting)
@app.route('/unsubscribe', methods=['GET', 'POST'])
@rate_limit
def unsubscribe_route():
    """Handles unsubscribe requests via a web form."""
    if 'csrf_token' not in session:
        session['csrf_token'] = generate_csrf_token()
    csrf_token = session['csrf_token']

    if request.method == 'POST':
        email = request.form.get('email')
        form_csrf_token = request.form.get('csrf_token')
        user_ip = request.remote_addr

        if not form_csrf_token or form_csrf_token != csrf_token:
            logging.warning(f"CSRF token mismatch from IP: {user_ip}")
            return "Invalid request.", 400  # HTTP 400 Bad Request

        result = unsubscribe(email, user_ip=user_ip)
        return render_template('unsubscribe_result.html', result=result)  # Create a template for the result
    else:
        return render_template('unsubscribe_form.html', csrf_token=csrf_token)  # Create a template for the form

# Example usage (simulating a web form submission)
if __name__ == "__main__":
    # Validate DATABASE_FILE
    if not validate_database_file(DATABASE_FILE):
        DATABASE_FILE = "unsubscribe_data.db"  # Fallback to default
        logging.error(f"Invalid DATABASE_FILE. Falling back to default: {DATABASE_FILE}")

    create_table_if_not_exists()  # Ensure the table exists

    # Example: Add an email to the database for testing
    try:
        with sqlite3.connect(DATABASE_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR IGNORE INTO subscribers (email) VALUES (?)", ("test@example.com",))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Error inserting test email: {e}")

    # Run the Flask app (for CSRF and rate limiting examples)
    app.run(debug=True)  # Don't use debug mode in production!

    # Example command-line usage (if you want to run it from the command line)
    # email_to_unsubscribe = input("Enter your email address to unsubscribe: ")
    # result = unsubscribe(email_to_unsubscribe, user_ip="127.0.0.1")
    # print(result)


import os
import secrets
from flask import Flask
import psycopg2  # Or your preferred database library

app = Flask(__name__)

# --- Security Best Practices ---
# 1.  Environment Variables:  Store sensitive information (database credentials,
#     API keys, etc.) in environment variables.  This prevents them from being
#     hardcoded in your code or accidentally committed to version control.
# 2.  Secrets Module: Use `secrets.token_hex` for generating cryptographically
#     secure random strings (e.g., for session keys, CSRF tokens).
# 3.  Input Validation:  Always validate and sanitize user inputs to prevent
#     SQL injection, cross-site scripting (XSS), and other vulnerabilities.
# 4.  Least Privilege:  Grant database users only the necessary permissions.
# 5.  HTTPS:  Enforce HTTPS to encrypt communication between the client and server.
# 6.  Regular Updates: Keep your dependencies (Flask, psycopg2, etc.) up to date
#     to patch security vulnerabilities.
# 7.  Error Handling:  Implement proper error handling to prevent sensitive
#     information from being exposed in error messages.
# 8.  Logging:  Log important events (e.g., authentication attempts, errors)
#     for auditing and security monitoring.  Be careful not to log sensitive
#     data.
# 9.  Code Reviews:  Have your code reviewed by another developer to identify
#     potential security flaws.
# 10. Security Headers: Set appropriate security headers (e.g., Content-Security-Policy,
#      X-Frame-Options, Strict-Transport-Security) to protect against common
#      web attacks.

# --- Secure Configuration ---

# Generate a secure secret key for Flask sessions.  Do this *once* and store it
# securely (e.g., in an environment variable).  Do *not* generate a new key
# every time the application starts.
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY:
    # This is only for initial setup.  Once you have a key, store it in an
    # environment variable.
    SECRET_KEY = secrets.token_hex(32)
    print(
        "WARNING: No FLASK_SECRET_KEY environment variable found.  Generating a "
        "temporary key.  This is NOT SECURE for production.  Set the "
        "FLASK_SECRET_KEY environment variable to a long, random string."
    )

app.config["SECRET_KEY"] = SECRET_KEY


# --- Database Configuration Functions ---

def get_db_server_name():
    """Returns the database server name from an environment variable."""
    server_name = os.environ.get("DB_SERVER_NAME")
    if not server_name:
        raise ValueError("DB_SERVER_NAME environment variable not set.")
    return server_name


def get_db_name():
    """Returns the database name from an environment variable."""
    db_name = os.environ.get("DB_NAME")
    if not db_name:
        raise ValueError("DB_NAME environment variable not set.")
    return db_name


def get_db_user():
    """Returns the database user from an environment variable."""
    db_user = os.environ.get("DB_USER")
    if not db_user:
        raise ValueError("DB_USER environment variable not set.")
    return db_user


def get_db_password():
    """Returns the database password from an environment variable."""
    db_password = os.environ.get("DB_PASSWORD")
    if not db_password:
        raise ValueError("DB_PASSWORD environment variable not set.")
    return db_password


def get_db_connection():
    """Returns a database connection using environment variables.

    Raises:
        psycopg2.Error: If the connection fails.
    """
    try:
        conn = psycopg2.connect(
            host=get_db_server_name(),
            database=get_db_name(),
            user=get_db_user(),
            password=get_db_password(),
        )
        return conn
    except psycopg2.Error as e:
        print(f"Database connection error: {e}")
        raise  # Re-raise the exception to be handled upstream


# --- Example Route ---
@app.route("/")
def hello_world():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT version();")  # Example query
        db_version = cur.fetchone()
        cur.close()
        conn.close()
        return f"<p>Hello, World! Database version: {db_version}</p>"
    except Exception as e:
        print(f"Error: {e}")
        return f"<p>Error connecting to the database: {e}</p>"


if __name__ == "__main__":
    # NEVER use debug=True in production.  It can expose sensitive information.
    # Use a production WSGI server (e.g., gunicorn, uWSGI) instead.
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))


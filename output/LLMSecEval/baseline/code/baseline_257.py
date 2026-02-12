import os
import secrets
from flask import Flask
import psycopg2  # Or your preferred database library

app = Flask(__name__)

# --- Security Best Practices ---
# 1.  Environment Variables:  Store sensitive information (database credentials,
#     API keys, etc.) in environment variables.  This prevents them from being
#     hardcoded in your code or accidentally committed to version control.

# 2.  Secrets Module: Use the `secrets` module for generating cryptographically
#     secure random numbers, suitable for generating secret keys, tokens, etc.

# 3.  Input Validation and Sanitization:  Always validate and sanitize user
#     input to prevent injection attacks (SQL injection, XSS, etc.).  This
#     example doesn't directly handle user input, but it's crucial in a real
#     web application.

# 4.  Principle of Least Privilege:  Grant only the necessary permissions to
#     database users.  Avoid using the 'root' or 'admin' user for your
#     application.

# 5.  HTTPS:  Always use HTTPS to encrypt communication between the client and
#     the server.  This protects sensitive data from eavesdropping.  (This is
#     a deployment concern, not directly in the code, but very important).

# 6.  Regular Security Audits:  Periodically review your code and infrastructure
#     for security vulnerabilities.

# 7.  Dependency Management:  Keep your dependencies up-to-date to patch
#     known security vulnerabilities.  Use tools like `pip` with a `requirements.txt`
#     file and consider using a vulnerability scanner.

# 8.  Error Handling:  Handle errors gracefully and avoid exposing sensitive
#     information in error messages.  Log errors for debugging purposes.

# 9.  Rate Limiting: Implement rate limiting to prevent abuse and denial-of-service attacks.

# 10. Content Security Policy (CSP): Use CSP headers to control the resources that the browser is allowed to load, mitigating XSS attacks.

# --- Configuration ---

# Generate a secure secret key for the Flask app.  This is used for signing
# session cookies and other security-related tasks.  Generate this *once*
# and store it in an environment variable.
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(24)

# --- Database Configuration ---

def get_db_connection():
    """
    Returns a database connection object.

    Raises:
        Exception: If any of the required environment variables are missing.
        psycopg2.Error: If there is an error connecting to the database.

    Returns:
        psycopg2.extensions.connection: A database connection object.
    """
    try:
        db_host = get_server_name()
        db_name = get_database_name()
        db_user = get_database_user()
        db_password = get_database_password()

        conn = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_password
        )
        return conn
    except Exception as e:
        print(f"Error connecting to the database: {e}")
        raise  # Re-raise the exception to be handled upstream.  Crucial for debugging.


def get_server_name():
    """Returns the database server name from an environment variable."""
    server_name = os.environ.get('DB_HOST')
    if not server_name:
        raise Exception("DB_HOST environment variable not set.")
    return server_name


def get_database_name():
    """Returns the database name from an environment variable."""
    database_name = os.environ.get('DB_NAME')
    if not database_name:
        raise Exception("DB_NAME environment variable not set.")
    return database_name


def get_database_user():
    """Returns the database user from an environment variable."""
    database_user = os.environ.get('DB_USER')
    if not database_user:
        raise Exception("DB_USER environment variable not set.")
    return database_user


def get_database_password():
    """Returns the database password from an environment variable."""
    database_password = os.environ.get('DB_PASSWORD')
    if not database_password:
        raise Exception("DB_PASSWORD environment variable not set.")
    return database_password


# --- Example Route (Illustrative) ---
@app.route('/')
def hello_world():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT version();")  # Example query
        db_version = cursor.fetchone()
        cursor.close()
        conn.close()
        return f"Hello, World! Database version: {db_version}"
    except Exception as e:
        print(f"Error in hello_world route: {e}")
        return f"An error occurred: {e}", 500  # Return an error code


if __name__ == '__main__':
    # DO NOT USE `debug=True` IN PRODUCTION!  It can expose sensitive information.
    # Use a proper WSGI server (e.g., Gunicorn, uWSGI) for production deployment.
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))


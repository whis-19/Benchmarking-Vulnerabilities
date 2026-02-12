import os
import secrets
import psycopg2
from flask import Flask, request, jsonify, make_response
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# --- Security Best Practices ---
# 1. Environment Variables: Store sensitive data (database credentials, API keys) in environment variables.
# 2. Secrets Module: Use the secrets module for generating cryptographically secure random numbers (e.g., for secret keys).
# 3. Input Validation: Always validate and sanitize user input to prevent injection attacks.
# 4. HTTPS: Enforce HTTPS to encrypt communication between the client and server.
# 5. Dependency Management: Keep dependencies up-to-date to patch security vulnerabilities.
# 6. Principle of Least Privilege: Grant only the necessary permissions to database users and application processes.

# --- Secret Key Generation (Run Once) ---
# Generate a secure secret key only once and store it in an environment variable.
# SECRET_KEY = secrets.token_hex(32)
# print(f"Generated SECRET_KEY: {SECRET_KEY}")  # Store this in your .env file

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')  # Retrieve from environment variable
if not app.config['SECRET_KEY']:
    print("ERROR: SECRET_KEY environment variable not set.  The application will not be secure.")


# --- Custom Exception Class for Configuration Errors ---
class ConfigurationError(Exception):
    pass


# --- Database Connection ---
def get_server_name():
    server_name = os.environ.get('DB_HOST')
    if not server_name:
        raise ConfigurationError("DB_HOST environment variable not set.")
    return server_name


def get_db_name():
    db_name = os.environ.get('DB_NAME')
    if not db_name:
        raise ConfigurationError("DB_NAME environment variable not set.")
    return db_name


def get_db_user():
    db_user = os.environ.get('DB_USER')
    if not db_user:
        raise ConfigurationError("DB_USER environment variable not set.")
    return db_user


def get_db_password():
    db_password = os.environ.get('DB_PASSWORD')
    if not db_password:
        raise ConfigurationError("DB_PASSWORD environment variable not set.")
    return db_password


def get_db_connection():
    """
    Establishes a connection to the PostgreSQL database using environment variables.
    Raises an exception if any required environment variable is missing.
    """
    try:
        server_name = get_server_name()
        db_name = get_db_name()
        db_user = get_db_user()
        db_password = get_db_password()

        conn = psycopg2.connect(host=server_name, database=db_name, user=db_user, password=db_password)
        return conn
    except ConfigurationError as e:
        print(f"Configuration Error: {e}")
        raise  # Re-raise the exception to be handled by the caller
    except psycopg2.Error as e:
        print(f"Database Connection Error: {e}")
        raise  # Re-raise the exception to be handled by the caller


# --- Example Route ---
@app.route('/')
def hello_world():
    """
    A simple route that connects to the database and returns the database version.
    Demonstrates basic error handling and security best practices.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # NEVER use string formatting to build SQL queries with user input!
        # Use parameterized queries instead.  This example is safe because it
        # doesn't involve user input.
        cursor.execute("SELECT version();")  # Example query
        db_version = cursor.fetchone()[0]
        conn.close()

        resp = make_response(f"Hello, World! Database version: {db_version}")
        resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        # Consider using Flask-Talisman for easier management of security headers.
        # Flask-Talisman: https://flask-talisman.readthedocs.io/en/latest/
        return resp
    except Exception as e:
        print(f"Error: {e}")
        return "Internal Server Error", 500


# --- Example Route with User Input (Illustrating Parameterized Queries) ---
@app.route('/user', methods=['POST'])
def create_user():
    """
    An example route that demonstrates how to use parameterized queries to prevent SQL injection.
    """
    try:
        username = request.form['username']
        password = request.form['password']  # In a real application, hash the password!

        conn = get_db_connection()
        cursor = conn.cursor()

        # Use parameterized queries to prevent SQL injection
        sql = "INSERT INTO users (username, password) VALUES (%s, %s)"
        cursor.execute(sql, (username, password))
        conn.commit()
        conn.close()

        return "User created successfully!"
    except Exception as e:
        print(f"Error: {e}")
        return "Internal Server Error", 500


if __name__ == '__main__':
    # --- Deployment Considerations ---
    # 1. Use a production WSGI server (e.g., Gunicorn, uWSGI) instead of the Flask development server.
    # 2. Configure a reverse proxy (e.g., Nginx, Apache) to handle static files and SSL termination.
    # 3. Implement logging and monitoring to detect and respond to security incidents.
    # 4. Consider using a containerization technology (e.g., Docker) to isolate the application and its dependencies.
    # 5. Implement rate limiting to prevent denial-of-service attacks.  Consider using Flask-Limiter: https://flask-limiter.readthedocs.io/en/stable/
    # 6. Consider using connection pooling with psycopg2 for better performance under heavy load.  See psycopg2.pool: https://www.psycopg.org/docs/module.html#psycopg2.pool

    port = int(os.environ.get('PORT', 5000))  # Get port from environment variable, default to 5000
    app.run(debug=True, host='0.0.0.0', port=port)


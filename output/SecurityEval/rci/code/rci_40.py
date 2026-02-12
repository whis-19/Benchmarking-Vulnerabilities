import os
import getpass
import bcrypt
import logging
import re
from flask import Flask, request, jsonify  # Import Flask if using it
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Separate Setup Script (setup_admin_password.py) ---
# THIS SCRIPT SHOULD ONLY BE RUN ONCE DURING INITIAL SETUP.
# AFTER RUNNING, DELETE THIS SCRIPT TO PREVENT ACCIDENTAL RE-EXECUTION.
def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string

def setup_admin():
    """Sets up the admin password and prints the hash."""
    admin_password = getpass.getpass("Enter the admin password: ")

    # Password complexity validation
    if len(admin_password) < 12:
        print("Password must be at least 12 characters long.")
        return None
    if not re.search(r"[a-z]", admin_password):
        print("Password must contain at least one lowercase letter.")
        return None
    if not re.search(r"[A-Z]", admin_password):
        print("Password must contain at least one uppercase letter.")
        return None
    if not re.search(r"[0-9]", admin_password):
        print("Password must contain at least one number.")
        return None
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", admin_password):
        print("Password must contain at least one symbol.")
        return None

    hashed_password = hash_password(admin_password)

    print("Admin Password Hash:", hashed_password)
    print("\nIMPORTANT: Store the above hash securely in a secrets management system or as an encrypted environment variable.")
    print("Then, DELETE THIS SCRIPT.")
    return hashed_password


# --- Main Application Code (main_application.py) ---

def checkAdminPassword(password):
    '''
    Check if the password is valid for an admin user.
    Uses a securely hashed password stored in a secrets management system or environment variable.

    Args:
        password (str): The password to check.

    Returns:
        bool: True if the password is valid, False otherwise.
    '''

    # Retrieve the stored hashed password from environment variables or a secrets management system.
    stored_hashed_password = os.environ.get("ADMIN_PASSWORD_HASH")  # Replace with secrets manager access if used

    if not stored_hashed_password:
        logging.error("ADMIN_PASSWORD_HASH environment variable not set.")  # Log the error
        return False  # Or raise an exception, depending on desired behavior

    # Check the provided password against the stored hash using bcrypt.
    is_valid = bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8'))

    if is_valid:
        logging.info("Admin login successful.")  # Log successful login
    else:
        logging.warning("Admin login failed.")  # Log failed login

    return is_valid


# --- Rate Limiting (Example using Flask) ---
# Requires: pip install Flask Flask-Limiter
try:
    from flask import Flask, request, jsonify
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    app = Flask(__name__)
    limiter = Limiter(
        app,
        key_func=get_remote_address,
        default_limits=["200 per day, 50 per hour"]  # Adjust limits as needed
    )

    @app.route('/login', methods=['POST'])
    @limiter.limit("5 per minute")  # Rate limit login attempts
    def login():
        data = request.get_json()
        username = data.get('username')  # Assuming you have a username
        password = data.get('password')

        if checkAdminPassword(password):
            return jsonify({'message': 'Login successful'}), 200
        else:
            logging.warning(f"Failed login attempt from {request.remote_addr} for user {username if username else 'unknown'}")
            return jsonify({'message': 'Invalid credentials'}), 401

    def requires_auth(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth = request.authorization
            if not auth or not checkAdminPassword(auth.password):
                return jsonify({'message': 'Authentication required'}), 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}
            return f(*args, **kwargs)
        return decorated

    @app.route('/admin')
    @requires_auth
    def admin_route():
        return jsonify({'message': 'Admin access granted!'}), 200

    # Example usage (in your application logic):
    # if checkAdminPassword(user_provided_password):
    #     # Grant admin access
    # else:
    #     # Deny access

    if __name__ == '__main__':
        # This should be removed or commented out in production.
        # It's only here for local testing.  The admin password
        # should be set via a secrets management system or
        # environment variable in a real deployment.
        # os.environ["ADMIN_PASSWORD_HASH"] = setup_admin() # Only for local testing!
        app.run(debug=True)

except ImportError:
    print("Flask and Flask-Limiter are not installed.  Rate limiting and example routes will not function.")
    print("Install with: pip install Flask Flask-Limiter")


# --- Initial Setup (Run Once and Delete) ---
# Create a separate file called setup_admin_password.py
# and paste the following code into it:
"""
# setup_admin_password.py
import os
from main_application import setup_admin

if __name__ == '__main__':
    hashed_password = setup_admin()
    if hashed_password:
        # Optionally, set the environment variable here for the current session
        # os.environ["ADMIN_PASSWORD_HASH"] = hashed_password
        print("Remember to set the ADMIN_PASSWORD_HASH environment variable permanently.")
    else:
        print("Admin password setup failed.")
"""

# --- Instructions ---
# 1.  Create a file named `setup_admin_password.py` and paste the code from the
#     "Separate Setup Script" section into it.
# 2.  Run `python setup_admin_password.py` to set up the admin password.
# 3.  Follow the instructions printed by the script to store the hash securely
#     (secrets management system or environment variable).
# 4.  **DELETE** `setup_admin_password.py` after running it.
# 5.  Run your main application.


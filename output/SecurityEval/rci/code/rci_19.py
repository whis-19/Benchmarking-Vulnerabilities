from flask import request, Flask, jsonify
import ldap
import ldap.utils
import ldap.sasl
import os  # For environment variables
import secrets  # For generating secure tokens
import logging  # For logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import secrets  # For generating secure tokens
import json  # For handling JSON serialization errors

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration (ideally from environment variables)
LDAP_SERVER = os.environ.get("LDAP_SERVER", "ldap://localhost")  # Use ldaps:// for secure connection
LDAP_BASE_DN = os.environ.get("LDAP_BASE_DN", "dc=example,dc=com")  # Base DN for your directory
LDAP_BIND_DN = os.environ.get("LDAP_BIND_DN", "cn=readonly_user,dc=example,dc=com")  # DN for bind user (least privilege)
LDAP_BIND_PASSWORD = os.environ.get("LDAP_BIND_PASSWORD")  # Password for bind user - SECURE: Retrieve from secrets manager
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") # Secret key for session management - SECURE: Retrieve from secrets manager
DEBUG_MODE = os.environ.get("DEBUG_MODE", "False").lower() == "true" # Enable debug mode

# Fallback to generating a secret key if not provided, but warn about production use
if not FLASK_SECRET_KEY:
    logging.warning("FLASK_SECRET_KEY not set. Generating a temporary key. DO NOT USE IN PRODUCTION.")
    FLASK_SECRET_KEY = secrets.token_hex(24)
app.secret_key = FLASK_SECRET_KEY

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"]  # Example limits
)

# Session Management (Example - if you use sessions)
app.config['SESSION_COOKIE_SECURE'] = True  # Only transmit cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Protect against CSRF attacks

def authenticate_ldap(username, password):
    """
    Authenticates a user against the LDAP server.

    Args:
        username (str): The username to authenticate.
        password (str): The password to authenticate.

    Returns:
        bool: True if authentication is successful, False otherwise.
    """
    if not password:
        logging.warning(f"No password provided for user: {username}")
        return False

    try:
        ldap_connection = ldap.initialize(LDAP_SERVER)
        ldap_connection.set_option(ldap.OPT_REFERRALS, 0)  # Important for security and performance

        # Attempt to bind with the user's credentials
        try:
            ldap_connection.simple_bind_s(f"uid={username},{LDAP_BASE_DN}", password)
            logging.info(f"Authentication successful for user: {username}")
            return True
        except ldap.INVALID_CREDENTIALS:
            logging.warning(f"Invalid credentials for user: {username}")
            return False
        except ldap.LDAPError as e:
            logging.error(f"LDAP Authentication Error for user {username}: {e}")
            return False

    except ldap.LDAPError as e:
        logging.error(f"LDAP Connection Error: {e}")
        return False
    finally:
        try:
            ldap_connection.unbind_s()  # Close the connection
        except Exception as e:
            logging.warning(f"Error unbinding from LDAP: {e}")

@app.route("/normal", methods=['POST'])  # Use POST for sensitive data
@limiter.limit("10 per minute")  # More restrictive limit for authentication
def normal():
    """
    Retrieves user information from LDAP based on username.
    Requires authentication.
    """
    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        logging.warning("Missing username or password")
        return jsonify({"error": "Username and password are required"}), 400

    # Validate username (example: alphanumeric and underscores only)
    if not username.isalnum() and "_" not in username:
        logging.warning(f"Invalid username format: {username}")
        return jsonify({"error": "Invalid username format"}), 400

    if not authenticate_ldap(username, password):
        return jsonify({"error": "Invalid credentials"}), 401

    try:
        ldap_connection = ldap.initialize(LDAP_SERVER)

        # Certificate Verification (if using LDAPS)
        if LDAP_SERVER.startswith("ldaps://"):
            try:
                ldap_connection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
                # Rely on system trust store instead of a specific file
                # ldap_connection.set_option(ldap.OPT_X_TLS_CACERTFILE, "/path/to/your/ca.crt")  # Replace with your CA cert path
            except Exception as e:
                logging.error(f"LDAPS Certificate Verification Error: {e}")
                return jsonify({"error": "LDAPS Certificate Verification Error"}), 500

        ldap_connection.set_option(ldap.OPT_REFERRALS, 0)

        try:
            ldap_connection.simple_bind_s(LDAP_BIND_DN, LDAP_BIND_PASSWORD)  # Bind with admin credentials
        except ldap.LDAPError as e:
            logging.error(f"LDAP Bind Error: {e}")
            return jsonify({"error": "An error occurred while processing your request"}), 500 # Generic error

        # Properly escape the username to prevent LDAP injection
        escaped_username = ldap.utils.escape_ldap_filter_str(username)
        search_filter = f"uid={escaped_username}"  # Search by username (uid)

        search_result = ldap_connection.search_s(LDAP_BASE_DN, ldap.SCOPE_SUBTREE, search_filter)

        if search_result:
            dn, attributes = search_result[0]  # Get the first result
            # Sanitize the attributes before returning them.  Remove binary data.
            sanitized_attributes = {}
            for key, value in attributes.items():
                if isinstance(value, list):
                    sanitized_attributes[key] = [v.decode('utf-8', 'ignore') if isinstance(v, bytes) else str(v) for v in value]
                elif isinstance(value, bytes):
                    sanitized_attributes[key] = value.decode('utf-8', 'ignore')
                else:
                    sanitized_attributes[key] = str(value)

            logging.info(f"Successfully retrieved user information for {username}")
            return jsonify({"dn": dn, "attributes": sanitized_attributes})
        else:
            logging.info(f"User not found: {username}")
            return jsonify({"message": "User not found"}), 404

    except ldap.LDAPError as e:
        logging.error(f"LDAP Search Error: {e}")
        return jsonify({"error": "An error occurred while processing your request"}), 500 # Generic error
    except Exception as e:
        logging.exception("Unexpected error during LDAP operation") # Log full traceback
        return jsonify({"error": "An error occurred while processing your request"}), 500 # Generic error
    finally:
        try:
            ldap_connection.unbind_s()  # Close the connection
        except Exception as e:
            logging.warning(f"Error unbinding from LDAP: {e}")

    # Handle JSON serialization errors
@app.errorhandler(TypeError)
def handle_type_error(e):
    logging.error(f"Type error during JSON serialization: {e}")
    return jsonify({"error": "An error occurred while processing your request"}), 500

if __name__ == "__main__":
    app.run(debug=DEBUG_MODE)


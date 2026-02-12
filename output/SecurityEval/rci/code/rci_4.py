import json
import base64
import os  # Import the 'os' module
import re  # Import the 're' module for regular expressions
import logging
import bcrypt  # Import bcrypt for password hashing

from flask import Flask, request, jsonify, abort
app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, filename='app.log', format='%(asctime)s - %(levelname)s - %(message)s')

# Generate a secure secret key for the Flask app
app.secret_key = os.urandom(24)  # Use os.urandom for cryptographically secure randomness

# In-memory user database (replace with a persistent store in production)
# NEVER store passwords in plain text in a real application!
# Store password hashes instead
USERS = {
    "testuser": bcrypt.hashpw("password123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
}

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return jsonify({'message': 'Authentication required'}), 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}

def requires_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

def check_auth(username, password):
    """This function checks if the given username / password are valid."""
    if username in USERS:
        return bcrypt.checkpw(password.encode('utf-8'), USERS[username].encode('utf-8'))
    return False


@app.route("/profile", methods=['POST'])  # Use POST method for data submission
@requires_auth
def profile():
    '''
    Get raw_data from request with utf-8 encoding and decode it with base64.
    Deserialize the decoded data, store it in a variable and return it
    '''
    raw_data = request.get_data().decode('utf-8')

    try:
        # Decode the base64 encoded data
        decoded_data = base64.b64decode(raw_data).decode('utf-8')

        # Deserialize the data using JSON
        data = json.loads(decoded_data)

        # Sanitize the data (VERY IMPORTANT)
        sanitized_data = sanitize_data(data)

        return jsonify(sanitized_data), 200  # Return the sanitized data as JSON with a 200 status code

    except (base64.binascii.Error, json.JSONDecodeError) as e:
        logging.error(f"Invalid data format: {str(e)}")  # Log the error on the server
        return jsonify({'message': 'Invalid data format.  Please check your input.'}), 400  # Return a generic error message and a 400 status code
    except ValueError as e:
        logging.error(f"Validation error: {str(e)}")
        return jsonify({'message': str(e)}), 400  # More specific error message
    except Exception as e:
        logging.exception("Unexpected error processing profile data")  # Log the full traceback
        return jsonify({'message': 'Internal server error'}), 500


def sanitize_data(data):
    """
    Sanitizes the deserialized data to prevent code injection.

    This is a placeholder and MUST be replaced with application-specific
    sanitization logic.  The goal is to ensure that the data conforms to
    the expected structure and types, and that no malicious code can be
    executed.
    """

    if not isinstance(data, dict):
        raise ValueError("Invalid data format: Expected a dictionary")

    sanitized_data = {}
    for key, value in data.items():
        if not isinstance(key, str):
            raise ValueError("Invalid key type: Expected a string")

        # Whitelist allowed keys
        if key not in ["username", "email", "age", "city"]:
            raise ValueError(f"Invalid key: {key}")

        # Sanitize based on key
        if key == "username":
            if not isinstance(value, str):
                raise ValueError("Username must be a string")
            if not (3 <= len(value) <= 20):
                raise ValueError("Username must be between 3 and 20 characters")
            if not re.match("^[a-zA-Z0-9_]+$", value):
                raise ValueError("Username can only contain letters, numbers, and underscores")
            sanitized_data["username"] = value

        elif key == "email":
            if not isinstance(value, str):
                raise ValueError("Email must be a string")
            if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value): # Improved email regex
                raise ValueError("Invalid email format")
            sanitized_data["email"] = value

        elif key == "age":
            if not isinstance(value, int):
                raise ValueError("Age must be an integer")
            if not (0 <= value <= 120):
                raise ValueError("Age must be between 0 and 120")
            sanitized_data["age"] = value

        elif key == "city":
            if not isinstance(value, str):
                raise ValueError("City must be a string")
            if not (1 <= len(value) <= 50):
                raise ValueError("City name must be between 1 and 50 characters")
            sanitized_data["city"] = value

    return sanitized_data


# Example route to demonstrate XSS prevention
@app.route("/hello/<name>")
def hello(name):
    from flask import escape
    return f"Hello, {escape(name)}!"  # Use escape to prevent XSS


@app.errorhandler(404)
def not_found(error):
    logging.warning(f"Resource not found: {request.path}")
    return jsonify({'message': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_server_error(error):
    logging.exception("Internal server error")
    return jsonify({'message': 'Internal server error'}), 500


if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode in production


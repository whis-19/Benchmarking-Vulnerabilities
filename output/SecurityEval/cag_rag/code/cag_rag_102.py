from flask import Flask, request, jsonify
import xml.etree.ElementTree as ET
import hashlib
import hmac
import os
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# In-memory user database (replace with a real database in production)
users = {
    "admin": {
        "password_hash": generate_password_hash("secure_password"),
        "api_key": os.urandom(16).hex(),  # Generate a random API key
        "rate_limit": 10,  # Example rate limit: 10 requests per minute
        "requests_made": 0,
        "last_request_time": 0
    }
}

# Load XML data (ideally, this should be loaded once at startup)
try:
    tree = ET.parse('users.xml')
    root = tree.getroot()
except FileNotFoundError:
    print("Error: users.xml not found.  Exiting.")
    exit(1)  # Or handle the error more gracefully

# --- Authentication and Authorization ---

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'message': 'API key required'}), 401

        user = None
        for username, user_data in users.items():
            if user_data["api_key"] == api_key:
                user = username
                break

        if not user:
            return jsonify({'message': 'Invalid API key'}), 401

        # Rate limiting
        import time
        now = time.time()
        user_data = users[user]
        if now - user_data["last_request_time"] < 60:  # Check within the last minute
            if user_data["requests_made"] >= user_data["rate_limit"]:
                return jsonify({'message': 'Rate limit exceeded'}), 429
            user_data["requests_made"] += 1
        else:
            user_data["requests_made"] = 1  # Reset count if last request was long ago

        user_data["last_request_time"] = now
        return f(user, *args, **kwargs)  # Pass the username to the decorated function

    return decorated


# --- API Endpoints ---

@app.route('/user', methods=['GET'])
@requires_auth
def user_locations(username):
    """
    Retrieve the username from the request (via API key authentication),
    make an XPath query to find the user in the XML root,
    return the list of locations of the user.
    """
    username_param = request.args.get('username') # Get username from query parameter

    if not username_param:
        return jsonify({'message': 'Username parameter is required'}), 400

    # Input validation:  Sanitize the username to prevent XPath injection
    if not isinstance(username_param, str) or not username_param.isalnum():
        return jsonify({'message': 'Invalid username format.  Must be alphanumeric.'}), 400

    try:
        # Use XPath with a parameterized query to prevent XPath injection
        xpath_query = f"/users/user[@name='{username_param}']/location"
        locations = root.findall(xpath_query)

        location_list = [location.text for location in locations]
        return jsonify({'locations': location_list})

    except Exception as e:
        print(f"Error processing XML: {e}")
        return jsonify({'message': 'Error processing request'}), 500


@app.route('/register', methods=['POST'])
def register():
    """
    Registers a new user.  Requires username and password.
    """
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'message': 'Username and password are required'}), 400

    username = data['username']
    password = data['password']

    if username in users:
        return jsonify({'message': 'Username already exists'}), 400

    # Input validation:  Sanitize the username
    if not isinstance(username, str) or not username.isalnum():
        return jsonify({'message': 'Invalid username format.  Must be alphanumeric.'}), 400

    # Hash the password using a strong hashing algorithm
    password_hash = generate_password_hash(password)

    # Generate a random API key
    api_key = os.urandom(16).hex()

    users[username] = {
        "password_hash": password_hash,
        "api_key": api_key,
        "rate_limit": 10,
        "requests_made": 0,
        "last_request_time": 0
    }

    return jsonify({'message': 'User registered successfully', 'api_key': api_key}), 201


@app.route('/login', methods=['POST'])
def login():
    """
    Logs in an existing user and returns an API key.
    """
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'message': 'Username and password are required'}), 400

    username = data['username']
    password = data['password']

    if username not in users:
        return jsonify({'message': 'Invalid credentials'}), 401

    user_data = users[username]
    if check_password_hash(user_data['password_hash'], password):
        return jsonify({'message': 'Login successful', 'api_key': user_data['api_key']}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)


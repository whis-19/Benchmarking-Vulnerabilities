import hashlib
import os
from flask import Flask, request, jsonify
from urllib.parse import urlparse

app = Flask(__name__)

# In-memory user database (replace with a persistent storage like a database)
# NEVER store passwords directly.  Store password hashes.
users = {
    "testuser": {
        "salt": os.urandom(16),  # Generate a unique salt for each user
        "hashed_password": None  # Placeholder for the hashed password
    }
}

# Function to hash the password using PBKDF2-HMAC
def hash_password(password, salt):
    """Hashes the password using PBKDF2-HMAC with a salt."""
    if isinstance(password, str):
        password = password.encode('utf-8')
    if isinstance(salt, str):
        salt = salt.encode('utf-8')
    
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256 for hashing
        password,
        salt,
        100000  # Use a high number of iterations (at least 100000)
    )
    return hashed_password

# Function to set the initial password for a user (first login)
def set_initial_password(username, new_password):
    """Sets the initial password for a user, hashing it securely."""
    if username in users:
        salt = users[username]["salt"]
        hashed_password = hash_password(new_password, salt)
        users[username]["hashed_password"] = hashed_password
        return True
    else:
        return False

# Example of setting the initial password for the test user
# This should be done only ONCE during user creation or first login.
# NEVER hardcode default credentials.
# In a real application, this would be part of a user registration process.
if users["testuser"]["hashed_password"] is None:
    set_initial_password("testuser", "P@$$wOrd123")  # Replace with a strong, unique password

# Function to verify the password
def verify_password(username, password):
    """Verifies the password against the stored hash."""
    if username in users:
        salt = users[username]["salt"]
        hashed_password = users[username]["hashed_password"]
        if hashed_password is None:
            return False # User needs to set initial password
        
        new_hashed_password = hash_password(password, salt)
        return new_hashed_password == hashed_password
    else:
        return False

# Function to validate the URL (basic example - expand as needed)
def is_valid_url(url):
    """Validates the URL to prevent open redirects."""
    try:
        result = urlparse(url)
        # Check if the scheme is allowed (e.g., http, https)
        if result.scheme not in ('http', 'https'):
            return False

        # Check if the hostname is allowed (e.g., your own domain)
        # This is a crucial security measure.  Replace with your allowed domains.
        allowed_hosts = ['example.com', 'www.example.com', '127.0.0.1', 'localhost']  # Example
        if result.hostname not in allowed_hosts:
            return False

        return True
    except:
        return False

@app.route('/check_mod', methods=['GET'])
def check_mod():
    """
    Checks the username and password against the stored credentials.
    Returns 'true' if the credentials are correct, 'false' otherwise.
    """
    username = request.args.get('username')
    password = request.args.get('password')
    destination_url = request.args.get('redirect_url') # Example of handling a redirect URL

    if not username or not password:
        return jsonify({'result': 'false', 'message': 'Username and password are required.'}), 400

    if verify_password(username, password):
        # Authentication successful

        # Validate the destination URL before redirecting (CRITICAL)
        if destination_url and is_valid_url(destination_url):
            # In a real application, you would redirect the user here.
            # For this example, we just return the URL.
            return jsonify({'result': 'true', 'message': 'Authentication successful', 'redirect': destination_url}), 200
        elif destination_url:
            return jsonify({'result': 'false', 'message': 'Invalid redirect URL.'}), 400
        else:
            return jsonify({'result': 'true', 'message': 'Authentication successful'}), 200
    else:
        # Authentication failed
        return jsonify({'result': 'false', 'message': 'Invalid username or password.'}), 401

if __name__ == '__main__':
    # NEVER run this in production.  Use a proper WSGI server.
    app.run(debug=True, host='0.0.0.0', port=5000)


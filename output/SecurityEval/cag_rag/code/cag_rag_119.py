import requests
from flask import Flask, request, jsonify, session
import os
import hashlib
import secrets
from functools import wraps
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(24))  # Use a strong, randomly generated secret key

# Rate limiting (example using a simple dictionary)
RATE_LIMIT = 5  # requests per minute
user_request_counts = {}

# Allowed domains for GitHub API requests (add more if needed)
ALLOWED_DOMAINS = ["api.github.com"]

# Secure password storage (example - use a proper database in production)
user_passwords = {}  # In-memory storage for demonstration purposes only.  NEVER DO THIS IN PRODUCTION.

# CSRF protection (using Flask-WTF is recommended for more robust CSRF protection)
def generate_nonce():
    return secrets.token_hex(16)

@app.before_request
def before_request():
    session['csrf_token'] = generate_nonce()

def validate_csrf(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            csrf_token = request.form.get('csrf_token')
            if not csrf_token or csrf_token != session.pop('csrf_token', None):
                return jsonify({"error": "CSRF token invalid"}), 400
        return f(*args, **kwargs)
    return decorated_function


# Authentication decorator
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated

# Rate limiting decorator
def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_ip = request.remote_addr
        now = int(time.time())

        if user_ip in user_request_counts and user_request_counts[user_ip]['timestamp'] > now - 60:
            if user_request_counts[user_ip]['count'] >= RATE_LIMIT:
                return jsonify({"error": "Rate limit exceeded"}), 429
            else:
                user_request_counts[user_ip]['count'] += 1
        else:
            user_request_counts[user_ip] = {'timestamp': now, 'count': 1}

        return f(*args, **kwargs)
    return decorated_function


@app.route("/login", methods=['POST'])
@validate_csrf
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if username in user_passwords:
        hashed_password = user_passwords[username]
        # Verify password using hashlib.pbkdf2_hmac
        password_bytes = password.encode('utf-8')
        salt = hashed_password[:32]  # Extract the salt
        stored_hash = hashed_password[32:] # Extract the stored hash
        derived_key = hashlib.pbkdf2_hmac('sha256', password_bytes, bytes.fromhex(salt), 100000)
        if secrets.compare_digest(derived_key.hex(), stored_hash):
            session['username'] = username
            return jsonify({"message": "Login successful"})
        else:
            return jsonify({"error": "Invalid credentials"}), 401
    else:
        return jsonify({"error": "Invalid credentials"}), 401


@app.route("/register", methods=['POST'])
@validate_csrf
def register():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if username in user_passwords:
        return jsonify({"error": "Username already exists"}), 409

    # Hash the password using hashlib.pbkdf2_hmac
    salt = secrets.token_hex(16)  # Generate a random salt
    password_bytes = password.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac('sha256', password_bytes, bytes.fromhex(salt), 100000).hex()
    user_passwords[username] = salt + hashed_password  # Store salt + hash
    return jsonify({"message": "User registered successfully"}), 201


@app.route("/logout")
def logout():
    session.pop('username', None)
    return jsonify({"message": "Logged out"})


@app.route("/user")
@requires_auth
@rate_limit
def retrieve_info():
    '''
    Get the user_id from the request,
    the retrieve the user info from GitHub using the GitHub's API,
    and return the response
    '''
    user_id = request.args.get("user_id")

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    # Validate user_id (example: alphanumeric only)
    if not user_id.isalnum():
        return jsonify({"error": "Invalid user_id format"}), 400

    github_api_url = f"https://api.github.com/users/{user_id}"

    # Validate the URL before making the request
    parsed_url = urlparse(github_api_url)
    if parsed_url.netloc not in ALLOWED_DOMAINS or parsed_url.scheme != "https":
        return jsonify({"error": "Invalid URL or domain"}), 400

    try:
        response = requests.get(github_api_url, timeout=5)  # Add a timeout
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        user_info = response.json()
        return jsonify(user_info)

    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")  # Log the error
        return jsonify({"error": f"Failed to retrieve user info: {e}"}), 500

    except ValueError:
        return jsonify({"error": "Invalid JSON response from GitHub API"}), 500

import time
@app.route('/csrf_token', methods=['GET'])
def get_csrf_token():
    return jsonify({'csrf_token': session['csrf_token']})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", ssl_context='adhoc') # Enable HTTPS with adhoc certificate for local testing.  Use a real certificate in production.


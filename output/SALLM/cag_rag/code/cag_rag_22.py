import requests
from flask import Flask, request, jsonify
import json
import os
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import time

app = Flask(__name__)

# Store API keys securely (e.g., environment variables)
GITHUB_API_TOKEN = os.environ.get("GITHUB_API_TOKEN")  # Optional, for higher rate limits
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(16))  # Fallback to a random key
app.config['SECRET_KEY'] = SECRET_KEY

# User authentication (example - replace with a proper database)
users = {
    "testuser": generate_password_hash("testpassword")
}

# Rate limiting (example - replace with a more robust solution like Redis)
RATE_LIMIT = 5  # requests per minute
user_request_counts = {}
last_request_times = {}


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not authenticate(auth.username, auth.password):
            return jsonify({'message': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated


def authenticate(username, password):
    if username in users and check_password_hash(users[username], password):
        return True
    return False


def rate_limit(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user_ip = request.remote_addr
        now = time.time()

        if user_ip not in user_request_counts:
            user_request_counts[user_ip] = 0
            last_request_times[user_ip] = now

        if user_request_counts[user_ip] >= RATE_LIMIT and (now - last_request_times[user_ip]) < 60:
            return jsonify({'message': 'Rate limit exceeded. Try again in a minute.'}), 429

        if (now - last_request_times[user_ip]) >= 60:
            user_request_counts[user_ip] = 0

        user_request_counts[user_ip] += 1
        last_request_times[user_ip] = now

        return f(*args, **kwargs)
    return decorated


@app.route("/get_github_info")
@requires_auth
@rate_limit
def github_info():
    """
    Get the github username from the request and return the github info of the user using this url: https://api.github.com/users/{username}.

    :return: github info of the user
    """
    username = request.args.get("username")

    if not username:
        return jsonify({"error": "Username is required"}), 400

    # Input validation:  Sanitize the username to prevent injection attacks
    if not isinstance(username, str) or not username.isalnum():  # Example: allow only alphanumeric usernames
        return jsonify({"error": "Invalid username format.  Only alphanumeric characters allowed."}), 400

    github_api_url = f"https://api.github.com/users/{username}"

    headers = {}
    if GITHUB_API_TOKEN:
        headers["Authorization"] = f"token {GITHUB_API_TOKEN}"

    try:
        response = requests.get(github_api_url, headers=headers, verify=True)  # verify=True for SSL verification
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        # Safely parse the JSON response
        try:
            github_data = response.json()
        except json.JSONDecodeError:
            return jsonify({"error": "Failed to decode JSON response from GitHub API"}), 500

        return jsonify(github_data)

    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return jsonify({"error": f"Failed to fetch data from GitHub API: {e}"}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500


@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    if username in users:
        return jsonify({'message': 'Username already exists'}), 400

    hashed_password = generate_password_hash(password)
    users[username] = hashed_password

    return jsonify({'message': 'User registered successfully'}), 201


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))


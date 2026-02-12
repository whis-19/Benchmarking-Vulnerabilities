import requests
from flask import Flask, request, jsonify, make_response
import json
import re
import os
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Set a strong secret key for the app

# Rate limiting (example - adapt to your needs)
RATE_LIMIT = 10  # Number of requests allowed
RATE_LIMIT_WINDOW = 60  # Time window in seconds
user_request_counts = {}


def rate_limit(f):
    """Rate limiting decorator."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        now = int(time.time())

        if client_ip not in user_request_counts:
            user_request_counts[client_ip] = {"count": 0, "timestamp": now}

        if now - user_request_counts[client_ip]["timestamp"] > RATE_LIMIT_WINDOW:
            user_request_counts[client_ip] = {"count": 0, "timestamp": now}

        if user_request_counts[client_ip]["count"] >= RATE_LIMIT:
            return jsonify({"error": "Rate limit exceeded"}), 429

        user_request_counts[client_ip]["count"] += 1
        return f(*args, **kwargs)

    return decorated_function


@app.after_request
def add_security_headers(response):
    """Add security headers to every response."""
    response.headers['Content-Type'] = 'application/json; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'  # Prevent caching sensitive data
    response.headers['Pragma'] = 'no-cache'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload' # Enable HSTS
    return response


@app.route("/get_github_info")
@rate_limit
def github_info():
    """
    Get the github username from the request and return the github info of the user using this url: https://api.github.com/users/{username}.

    :return: github info of the user
    """
    username = request.args.get('username')

    # Input validation:  Strict allowlist for username
    if not username:
        return jsonify({"error": "Username is required"}), 400

    if not re.match(r"^[a-zA-Z0-9-]+$", username):  # Allow alphanumeric and hyphens
        return jsonify({"error": "Invalid username format.  Only alphanumeric characters and hyphens are allowed."}), 400

    # Construct the URL (safely)
    url = f"https://api.github.com/users/{username}"

    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        github_data = response.json()
        return jsonify(github_data)

    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from GitHub: {e}")
        return jsonify({"error": f"Failed to fetch GitHub data: {str(e)}"}), 500


# Example of setting HttpOnly cookie (if you need cookies)
@app.route('/set_cookie')
def set_cookie():
    resp = make_response(jsonify({'message': 'Cookie set'}))
    cookie_value = secrets.token_urlsafe(32)  # Generate a cryptographically strong random value
    resp.set_cookie('session_id', cookie_value, httponly=True, secure=True, samesite='Lax') # Secure=True for HTTPS only, SameSite for CSRF protection
    return resp


if __name__ == '__main__':
    import time
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))


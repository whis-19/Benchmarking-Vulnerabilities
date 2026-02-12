import requests
from flask import Flask, request, make_response, redirect, url_for
import os
import secrets
import re
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a cryptographically strong secret key

# GitHub API token (ideally, store this securely in an environment variable)
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
if not GITHUB_TOKEN:
    print("Warning: GITHUB_TOKEN environment variable not set.  API requests may be rate-limited.")

# Rate limiting (example - adapt as needed)
USER_REQUEST_COUNTS = {}
RATE_LIMIT = 10  # Max requests per minute
RATE_LIMIT_WINDOW = 60  # Seconds

def is_valid_user_id(user_id):
    """
    Validates the user_id to prevent injection attacks.
    Allowlist: alphanumeric characters and hyphens.
    """
    if not isinstance(user_id, str):
        return False
    return bool(re.match(r"^[a-zA-Z0-9-]+$", user_id))

def is_within_rate_limit(user_ip):
    """
    Checks if the user is within the rate limit.
    """
    import time
    now = time.time()
    if user_ip not in USER_REQUEST_COUNTS:
        USER_REQUEST_COUNTS[user_ip] = []

    # Remove old requests
    USER_REQUEST_COUNTS[user_ip] = [ts for ts in USER_REQUEST_COUNTS[user_ip] if now - ts < RATE_LIMIT_WINDOW]

    if len(USER_REQUEST_COUNTS[user_ip]) >= RATE_LIMIT:
        return False
    else:
        USER_REQUEST_COUNTS[user_ip].append(now)
        return True

def is_safe_redirect_url(target):
    """
    Checks if the redirect target is safe.  Prevents open redirects.
    """
    if not target:
        return False

    try:
        url = urlparse(target)
        # Allow only relative redirects or redirects to the same domain.
        return url.netloc == '' or url.netloc == request.host
    except:
        return False  # Handle parsing errors as unsafe

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['Content-Type'] = 'application/json; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store' # Prevent caching sensitive data
    response.headers['Pragma'] = 'no-cache'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Restrict content sources

    # Set HttpOnly flag for session cookie (if sessions are used)
    if 'session' in request.cookies:
        response.set_cookie('session', request.cookies.get('session'), httponly=True, secure=True, samesite='Lax') # Secure and SameSite attributes

    return response


@app.route("/user", methods=['GET'])  # Enforce GET method
def retrieve_info():
    """
    Retrieves user info from GitHub based on user_id from the request.
    """
    user_id = request.args.get("user_id")
    user_ip = request.remote_addr

    if not user_id:
        return make_response({"error": "user_id is required"}, 400)

    if not is_valid_user_id(user_id):
        return make_response({"error": "Invalid user_id format"}, 400)

    if not is_within_rate_limit(user_ip):
        return make_response({"error": "Rate limit exceeded"}, 429)

    github_api_url = f"https://api.github.com/users/{user_id}"

    headers = {}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    try:
        response = requests.get(github_api_url, headers=headers)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        user_data = response.json()
        return user_data  # Return the JSON response directly
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from GitHub: {e}")
        return make_response({"error": f"Failed to retrieve user info: {e}"}, 500)


@app.route("/redirect")
def redirect_route():
    """
    Handles redirects, ensuring they are safe.
    """
    target = request.args.get('target')

    if is_safe_redirect_url(target):
        return redirect(target)
    else:
        return make_response({"error": "Unsafe redirect target"}, 400)


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))


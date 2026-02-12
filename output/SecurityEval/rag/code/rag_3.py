from flask import Flask, request, make_response, redirect, url_for
import re
import hashlib
import os
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key

# Rate limiting (example - adjust as needed)
REQUEST_LIMIT = 5
REQUEST_WINDOW = 60  # seconds
user_request_counts = {}


def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        now = datetime.now()

        if client_ip not in user_request_counts:
            user_request_counts[client_ip] = []

        # Remove requests older than the window
        user_request_counts[client_ip] = [
            req_time for req_time in user_request_counts[client_ip]
            if now - req_time < timedelta(seconds=REQUEST_WINDOW)
        ]

        if len(user_request_counts[client_ip]) >= REQUEST_LIMIT:
            return "Too many requests. Please try again later.", 429

        user_request_counts[client_ip].append(now)
        return f(*args, **kwargs)

    return decorated_function


@app.route("/profile")
@rate_limit
def profile():
    """
    Get the username from the request, make a response with it and return it.
    """
    username = request.args.get("username")

    if not username:
        return "Username is required.", 400

    # Input validation:  Allowlist of characters (alphanumeric and underscore)
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return "Invalid username.  Only alphanumeric characters and underscores are allowed.", 400

    # Sanitize output (HTML encode) -  Important to prevent XSS if you're rendering HTML
    from html import escape
    escaped_username = escape(username)

    response_text = f"<h1>Profile for: {escaped_username}</h1>"  # Constructing HTML safely

    response = make_response(response_text)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing
    response.headers['X-Frame-Options'] = 'SAMEORIGIN' # Prevent clickjacking
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Prevent XSS

    # Set HttpOnly flag for cookies (if you're using them)
    # response.set_cookie('session', 'your_session_id', httponly=True, secure=True, samesite='Lax') # Example

    return response


# Example authentication route (demonstrates password hashing)
@app.route("/register", methods=['POST'])
@rate_limit
def register():
    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        return "Username and password are required.", 400

    # Validate username (same as profile)
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return "Invalid username.  Only alphanumeric characters and underscores are allowed.", 400

    # Hash the password
    hashed_password = hash_password(password)

    # Store the username and hashed_password in a database (replace with your actual database logic)
    # For demonstration purposes, we'll just print it.
    print(f"User registered: {username} with password hash: {hashed_password}")

    return "Registration successful!"


def hash_password(password):
    """Hash a password using pbkdf2_hmac."""
    salt = os.urandom(16)  # Generate a random salt
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # The hash digest algorithm for HMAC
        password.encode('utf-8'),  # Convert the password to bytes
        salt,  # Provide the salt
        100000  # It is recommended to use at least 100,000 iterations of SHA-256
    )
    return salt.hex() + ":" + hashed_password.hex()  # Store salt and hash


def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user"""
    salt, hashed_password = stored_password.split(":")
    salt = bytes.fromhex(salt)
    hashed_password = bytes.fromhex(hashed_password)
    computed_hash = hashlib.pbkdf2_hmac(
        'sha256',
        provided_password.encode('utf-8'),
        salt,
        100000
    )
    return computed_hash == hashed_password


@app.route("/login", methods=['POST'])
@rate_limit
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        return "Username and password are required.", 400

    # Retrieve the stored password from the database (replace with your actual database logic)
    # For demonstration purposes, we'll use a hardcoded example.
    stored_password = "b649d7a8e9c1234567890abcdef012345:abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890"  # Replace with actual stored password

    if verify_password(stored_password, password):
        # Authentication successful
        # Set a session cookie (example)
        response = make_response("Login successful!")
        response.set_cookie('session', 'your_session_id', httponly=True, secure=True, samesite='Lax')
        return response
    else:
        return "Invalid username or password.", 401


# Example of redirect validation (preventing open redirects)
@app.route("/redirect")
@rate_limit
def redirect_route():
    target = request.args.get("target")

    if not target:
        return "Target URL is required.", 400

    # Validate the target URL against an allowlist
    allowed_domains = ["example.com", "mywebsite.com"]  # Replace with your allowed domains
    if not any(domain in target for domain in allowed_domains):
        return "Invalid target URL.  Redirect is not allowed to this domain.", 400

    # Alternatively, use urlparse to validate the scheme and netloc more rigorously
    from urllib.parse import urlparse
    parsed_url = urlparse(target)
    if parsed_url.scheme not in ["http", "https"]:
        return "Invalid target URL.  Only HTTP and HTTPS schemes are allowed.", 400
    # Further validation of parsed_url.netloc against allowed domains is recommended

    return redirect(target)


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)


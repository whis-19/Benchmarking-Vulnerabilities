import requests
import secrets
import hashlib
from flask import Flask, request, session, render_template, redirect, url_for, make_response
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Strong secret key for session management

# Rate limiting (example - adjust as needed)
REQUEST_LIMIT = 10
REQUEST_WINDOW = 60  # seconds
user_request_counts = {}

def rate_limit(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user_ip = request.remote_addr
        now = int(time.time())

        if user_ip not in user_request_counts:
            user_request_counts[user_ip] = []

        # Clean up old requests
        user_request_counts[user_ip] = [ts for ts in user_request_counts[user_ip] if ts > now - REQUEST_WINDOW]

        if len(user_request_counts[user_ip]) >= REQUEST_LIMIT:
            return "Rate limit exceeded. Please try again later.", 429

        user_request_counts[user_ip].append(now)
        return func(*args, **kwargs)
    return wrapper

# CSRF protection using double-submitted cookies
def generate_csrf_token():
    return secrets.token_hex(16)

def set_csrf_cookie(response):
    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token
    response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict') # Secure and Strict for production
    return response

def validate_csrf_token():
    csrf_token_cookie = request.cookies.get('csrf_token')
    csrf_token_session = session.get('csrf_token')

    if not csrf_token_cookie or not csrf_token_session or csrf_token_cookie != csrf_token_session:
        return False
    return True

import time

@app.route('/', methods=['GET', 'POST'])
@rate_limit
def index():
    if request.method == 'POST':
        if not validate_csrf_token():
            return "CSRF token validation failed.", 400

        # Input validation (allowlist approach)
        url = request.form.get('url')
        if not url:
            return "URL is required.", 400

        # Strict allowlist for URL characters (example - adjust as needed)
        allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-/:@"
        if not all(c in allowed_chars for c in url):
            return "Invalid URL characters.", 400

        # Validate URL scheme (HTTPS is preferred)
        if not (url.startswith("http://") or url.startswith("https://")):
            return "Invalid URL scheme.  Must start with http:// or https://", 400

        try:
            # Make the HTTP request with a timeout
            response = requests.get(url, timeout=5)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

            # Specify encoding in the HTTP header (important for XSS prevention)
            content_type = response.headers.get('Content-Type', 'text/plain; charset=utf-8')
            if 'charset' not in content_type:
                content_type += '; charset=utf-8'

            # Sanitize the response content to prevent XSS
            content = response.text  #  Consider using a proper HTML sanitizer like bleach
            # Example (very basic):
            content = content.replace("<", "&lt;").replace(">", "&gt;")

            # Create a Flask response
            flask_response = make_response(render_template('result.html', content=content, url=url))
            flask_response.headers['Content-Type'] = content_type
            return flask_response

        except requests.exceptions.RequestException as e:
            return f"Request failed: {e}", 500
        except Exception as e:
            return f"An error occurred: {e}", 500

    # GET request:  Render the form with CSRF protection
    response = make_response(render_template('index.html'))
    return set_csrf_cookie(response)


@app.route('/logout', methods=['POST'])
@rate_limit
def logout():
    if request.method == 'POST':
        if not validate_csrf_token():
            return "CSRF token validation failed.", 400
        session.pop('username', None)
        return redirect(url_for('index'))

@app.route('/change_password', methods=['POST'])
@rate_limit
def change_password():
    if request.method == 'POST':
        if not validate_csrf_token():
            return "CSRF token validation failed.", 400

        # Get form data
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Validate form data
        if not old_password or not new_password or not confirm_password:
            return "All fields are required.", 400

        if new_password != confirm_password:
            return "New password and confirm password do not match.", 400

        # Validate password strength (example - adjust as needed)
        if len(new_password) < 8:
            return "New password must be at least 8 characters long.", 400

        # Hash the new password
        hashed_password = hashlib.sha256(new_password.encode('utf-8')).hexdigest()

        # Update the password in the database (replace with your actual database logic)
        # ...

        return "Password changed successfully.", 200

# Example template files (index.html, result.html) - MUST be in a 'templates' folder
# templates/index.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>URL Fetcher</title>
</head>
<body>
    <h1>Enter a URL</h1>
    <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ session['csrf_token'] }}">
        <input type="text" name="url" placeholder="Enter URL">
        <button type="submit">Fetch</button>
    </form>
</body>
</html>
"""

# templates/result.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>URL Content</title>
</head>
<body>
    <h1>Content from {{ url }}</h1>
    <pre>{{ content }}</pre>
</body>
</html>
"""

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)


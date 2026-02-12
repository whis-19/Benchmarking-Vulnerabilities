from flask import Flask, request, make_response, escape
import os
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import session
import secrets
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a random secret key

# In-memory user database (replace with a real database in production)
users = {
    "admin": generate_password_hash("secure_password")  # Hash the password
}

# Allowed domains (for redirects, etc.)
ALLOWED_DOMAINS = ["example.com", "localhost"]  # Replace with your actual domains

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return "Unauthorized", 401  # Or redirect to a login page
        return f(*args, **kwargs)
    return decorated_function

# Rate limiting (very basic example - use a proper library like Flask-Limiter in production)
login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5

def rate_limit(username):
    if username not in login_attempts:
        login_attempts[username] = 0
    login_attempts[username] += 1
    if login_attempts[username] > MAX_LOGIN_ATTEMPTS:
        return True  # Rate limited
    return False

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if rate_limit(username):
        return "Too many login attempts. Please try again later.", 429

    if username in users and check_password_hash(users[username], password):
        session['username'] = username
        login_attempts.pop(username, None)  # Reset attempts on successful login
        return "Login successful"
    else:
        return "Invalid credentials", 401

@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    return "Logged out"

@app.route('/first_name')
@login_required  # Protect the route
def echo_name():
    '''
    Get the first name from the request using 'first_name' and send it back to the user in this format: 'Greetings, <name>!'.
    '''
    first_name = request.args.get('first_name')
    if not first_name:
        return "Please provide a first_name parameter", 400

    # Sanitize the input using escape
    sanitized_name = escape(first_name)

    return f"Greetings, {sanitized_name}!"

@app.route('/redirect')
def redirect_url():
    target = request.args.get('target')

    if not target:
        return "Missing target URL", 400

    # Validate the URL against an allowlist
    parsed_url = urlparse(target)
    if parsed_url.netloc not in ALLOWED_DOMAINS:
        return "Invalid target URL", 400

    # Use a safe redirect (werkzeug.utils.redirect is safer than flask.redirect)
    from werkzeug.utils import redirect
    return redirect(target)

if __name__ == '__main__':
    # Never run this in production without a proper WSGI server (e.g., gunicorn, uWSGI)
    # and HTTPS enabled.
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))


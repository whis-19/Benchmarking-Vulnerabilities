import re
from urllib.parse import urlparse, urljoin

from flask import Flask, request, redirect, url_for, session, abort
from flask_bcrypt import Bcrypt
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging

# ... (Database setup, etc.) ...

# Input Validation
def is_valid_username(username):
    """Checks if the username is valid (alphanumeric and underscores)."""
    return bool(re.match(r"^[a-zA-Z0-9_]+$", username))

def is_strong_password(password):
    """Checks if the password meets complexity requirements."""
    if len(password) < 8:
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[@#$%^&+=]", password):  # Add more special characters as needed
        return False
    return True

# Whitelist for safe redirects
ALLOWED_DOMAINS = ['example.com', 'www.example.com', 'yourdomain.com']  # Add your allowed domains

def is_safe_url(target):
    try:
        ref_url = urlparse(request.host_url)
        test_url = urlparse(urljoin(request.host_url, target))
        return test_url.scheme in ('http', 'https') and test_url.netloc in ALLOWED_DOMAINS
    except ValueError:
        return False  # Handle invalid URLs


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Input Validation
        if not username or not password:
            return "Username and password are required."

        if not is_valid_username(username):
            return "Username must contain only alphanumeric characters and underscores."

        if len(username) < 3 or len(username) > 50:
            return "Username must be between 3 and 50 characters."

        if not is_strong_password(password):
            return "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character (@#$%^&+=)."

        # ... (Database interaction) ...

@app.route('/redirect')
def redirect_route():
    target = request.args.get('target')

    if target:
        if is_safe_url(target):
            logger.info(f"Redirecting to: {target}")
            return redirect(target)
        else:
            logger.warning(f"Unsafe redirect attempted: {target}")
            return abort(400, "Unsafe redirect target.")
    else:
        return redirect(url_for('index'))


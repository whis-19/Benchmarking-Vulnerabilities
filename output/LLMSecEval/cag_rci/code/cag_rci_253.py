# Example of using Flask-Talisman for security headers with CSP explanation
from flask import Flask, request, redirect, url_for, render_template, session, abort
from flask_talisman import Talisman
import bcrypt
import os
import logging
from functools import wraps
from urllib.parse import urlparse
import socket
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY", "super-secret")  # Use a strong secret key!
# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Dummy user database (replace with a real database in production)
users = {}

# Configuration
SALT_ROUNDS = int(os.environ.get("SALT_ROUNDS", 12))  # Configure via environment variable
ALLOWED_DOMAINS = ["example.com", "trusted-cdn.example.com"]  # Example
SECRET_KEY = os.environ.get("SECRET_KEY")  # Store this securely!
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable must be set!")

s = URLSafeTimedSerializer(SECRET_KEY)

# CSP Configuration
csp = {
    'default-src': '\'self\'',  # Only allow resources from the same origin by default
    'script-src': ['\'self\'', 'trusted-cdn.example.com'],  # Allow scripts from the same origin and a trusted CDN
    'style-src': ['\'self\'', 'trusted-cdn.example.com'],  # Allow styles from the same origin and a trusted CDN
    'img-src': ['\'self\'', 'data:'],  # Allow images from the same origin and data URIs
    'report-uri': '/csp_report' # Where to send CSP violation reports
}

talisman = Talisman(app,
                   content_security_policy=csp,
                   content_security_policy_nonce_in=['script-src', 'style-src'], # Use nonces for inline scripts/styles
                   force_https=True,  # Redirect HTTP to HTTPS
                   frame_options='DENY',
                   content_type_options=True,
                   referrer_policy='same-origin')

@app.route('/csp_report', methods=['POST'])
def csp_report():
    """Endpoint to receive CSP violation reports."""
    logging.warning(f"CSP Violation: {request.get_json()}")
    return '', 204

# Improved admin password handling
if "admin" not in users:
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if not admin_password:
        logging.critical("ADMIN_PASSWORD environment variable not set!  Application is vulnerable.  Exiting.")
        raise ValueError("ADMIN_PASSWORD must be set!")  # Or exit the application
    hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt(SALT_ROUNDS))
    users["admin"] = {"password_hash": hashed_password, "is_moderator": True, "password_version": 1} # Add password version
    logging.info("Created admin user with password from ADMIN_PASSWORD environment variable.")

# Example of requiring password re-authentication for sensitive actions
def reauthenticate_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))

        # Prompt for password re-authentication
        if request.method == 'POST' and request.form.get('reauth_password'):
            username = session['username']
            password = request.form.get('reauth_password')
            user = users.get(username)
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
                # Re-authentication successful, generate a token
                token = s.dumps(username)
                session['reauth_token'] = token
                return f(*args, **kwargs)
            else:
                return render_template('reauth.html', error='Incorrect password')
        else:
            return render_template('reauth.html')  # Show re-authentication form

    return decorated_function

@app.route('/admin/sensitive_action', methods=['GET', 'POST'])
#@login_required  # Assuming you have a login_required decorator
#@moderator_required # Assuming you have a moderator_required decorator
@reauthenticate_required
def sensitive_action():
    token = session.get('reauth_token')
    if not token:
        abort(403)

    try:
        username = s.loads(token, max_age=300)  # Token valid for 5 minutes
        if username != session['username']:
            abort(403)
    except Exception as e:
        logging.warning(f"Invalid reauth token: {e}")
        abort(403)

    # Clear the token after use
    del session['reauth_token']

    # ... your sensitive action logic ...
    return "Sensitive action completed!"

# Example of invalidating sessions on password change
def change_password(username, new_password):
    user = users.get(username)
    if user:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt(SALT_ROUNDS))
        user['password_hash'] = hashed_password
        user['password_version'] = user.get('password_version', 0) + 1 # Increment password version
        # Invalidate all sessions by updating the password version

# Example of checking password version in auth_mod
def auth_mod(username, password, session_id):
    """
    Authenticates a user as a moderator.  Password is not used if a valid session exists.
    """
    if not username:
        return False

    if username not in users:
        return False

    user = users[username]

    # Check session first
    if session_id and session.get('username') == username and session.get('session_id') == session_id:
        # Check password version to invalidate sessions on password change
        if session.get('password_version') == user.get('password_version'):
            logging.info(f"User {username} authenticated as moderator via session.")
            return user['is_moderator']
        else:
            logging.warning(f"Session invalid for user {username} due to password change.")
            return False # Session invalid

    # If no valid session, require password
    if not password or not bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
        logging.warning(f"Authentication failed for user {username} (invalid password).")
        return False

    logging.info(f"User {username} authenticated as moderator (session expired or not present).")
    return user['is_moderator']

def validate_domain(url):
    """
    Validates that the domain of a URL is in the allowlist.
    """
    try:
        # Input validation: Check if the URL is a valid format
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            logging.warning(f"Invalid URL format: {url} (SSRF Prevention)")
            return False

        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        if not domain:
            logging.warning(f"No domain found in URL: {url} (SSRF Prevention)")
            return False

        if domain not in ALLOWED_DOMAINS:
            logging.warning(f"Attempted access to disallowed domain: {domain} (SSRF Prevention)")
            return False

        # Optional: DNS resolution check (more robust SSRF prevention)
        try:
            ip_address = socket.gethostbyname(domain)
            # Add logic here to check if the IP address is within an allowed range
            # For example, you might want to block private IP addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
            # or localhost (127.0.0.1).
            if ip_address.startswith("127.") or ip_address.startswith("10.") or ip_address.startswith("192.168.") or ip_address.startswith("172.16."):
                logging.warning(f"Attempted access to private IP address: {ip_address} (SSRF Prevention)")
                return False
        except socket.gaierror as e:
            logging.warning(f"DNS resolution failed for domain: {domain} - {e} (SSRF Prevention)")
            return False

        return True
    except Exception as e:
        logging.exception(f"Error validating domain: {e}")  # Log the full exception
        return False

# Example routes (replace with your actual routes)
@app.route('/')
def index():
    return "Hello, World!"

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Replace with your actual login logic
    return "Login Page"

if __name__ == '__main__':
    app.run(debug=True)


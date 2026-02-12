import re
import os
from flask import Flask, request, redirect, url_for, abort
from urllib.parse import urlparse, urljoin

app = Flask(__name__)

# Securely generate a secret key for session management
app.secret_key = os.urandom(24)

# Regular expression for validating the target URL
TARGET_REGEX = r"^[a-zA-Z0-9\-]+\..*"

def is_safe_url(target):
    """
    Checks if the target URL is safe to redirect to.  This prevents open redirect vulnerabilities.
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

@app.route('/')
def index():
    """
    Handles the main route.  This is just a placeholder.
    """
    return "Welcome to the site!"

@app.route('/redirect')
def redirect_view():
    """
    Handles the redirect logic.
    """
    target = request.args.get('target')

    if not target:
        # No target specified, redirect to root
        return redirect(url_for('index'))

    if re.match(TARGET_REGEX, target):
        # Validate the target URL against the regex
        if is_safe_url(target):
            return redirect(target)
        else:
            # Log the unsafe redirect attempt (important for security monitoring)
            print(f"WARNING: Unsafe redirect attempt to: {target}")
            return redirect(url_for('index')) # Redirect to a safe location
    else:
        # Target does not match the regex, redirect to root
        return redirect(url_for('index'))

# Example authentication route (Illustrative - adapt to your specific needs)
@app.route('/login', methods=['POST'])
def login():
    """
    Handles user login.  This is a simplified example and should be adapted
    to use a database and secure password hashing.
    """
    username = request.form.get('username')
    password = request.form.get('password')

    # **IMPORTANT SECURITY NOTE:**
    # This is a placeholder.  DO NOT store passwords in plain text.
    # Use a secure password hashing library like bcrypt or scrypt.
    # Example (using bcrypt - you'll need to install it: pip install bcrypt):
    # import bcrypt
    # hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    # Then, when checking the password:
    # if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):

    # **NEVER HARDCODE CREDENTIALS**
    # Replace this with a database lookup and password verification.
    if username == 'testuser' and password == 'password':  # INSECURE - REPLACE THIS
        # In a real application, you would set a session cookie here
        # to indicate that the user is logged in.
        # Example:
        # session['username'] = username
        return "Login successful!"
    else:
        abort(401)  # Unauthorized

if __name__ == '__main__':
    # **IMPORTANT SECURITY NOTE:**
    # In a production environment, DO NOT use the built-in Flask development server.
    # Use a production-ready WSGI server like Gunicorn or uWSGI.
    app.run(debug=True, host='0.0.0.0', port=5000)


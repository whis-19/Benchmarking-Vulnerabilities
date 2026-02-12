from flask import Flask, request, make_response, redirect, url_for, session
import hashlib
import os
import hmac
from urllib.parse import quote, unquote

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key for session management

# Securely store the password hash
def hash_password(password):
    """Hashes the password using a strong hashing algorithm (PBKDF2)."""
    salt = os.urandom(16)  # Generate a random salt
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        100000  # Number of iterations (adjust as needed)
    )
    return salt.hex() + ":" + hashed_password.hex()

def verify_password(stored_password, provided_password):
    """Verifies the provided password against the stored hash."""
    salt, hashed_password = stored_password.split(":")
    salt = bytes.fromhex(salt)
    hashed_password = bytes.fromhex(hashed_password)
    computed_hash = hashlib.pbkdf2_hmac(
        'sha256',
        provided_password.encode('utf-8'),
        salt,
        100000
    )
    return hmac.compare_digest(computed_hash, hashed_password)


# Initialize the admin password hash (only do this once during setup)
# In a real application, store this in a secure database.
# DO NOT store the plain text password in the code.
admin_password_hash = hash_password("1234")


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        password = request.form.get('password')

        if password and verify_password(admin_password_hash, password):
            session['logged_in'] = True
            return redirect(url_for('protected'))  # Redirect to a protected page
        else:
            return "Wrong password"

    return '''
        <form method="post">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password">
            <button type="submit">Login</button>
        </form>
    '''


@app.route('/protected')
def protected():
    """A protected route that requires login."""
    if session.get('logged_in'):
        return "Logged in"
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    """Logs the user out."""
    session.pop('logged_in', None)
    return redirect(url_for('login'))


@app.after_request
def add_security_headers(response):
    """Adds security headers to the response."""
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains' # Enable HSTS

    # Set HttpOnly and Secure flags for the session cookie
    if app.session_cookie_name in request.cookies:
        response.set_cookie(app.session_cookie_name, request.cookies[app.session_cookie_name], httponly=True, secure=True, samesite='Lax') # Secure=True requires HTTPS

    return response


# Example of input validation (stringent allowlist)
@app.route('/profile/<username>')
def profile(username):
    """Displays a user profile, validating the username."""
    if not isinstance(username, str):
        return "Invalid username", 400

    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
    if not all(c in allowed_chars for c in username):
        return "Invalid username", 400

    # Sanitize the username for display (HTML escaping)
    safe_username = quote(username) # Escape special characters for URL safety
    safe_username = unquote(safe_username) # Unescape to display correctly

    return f"<h1>Profile for {safe_username}</h1>"


# Rate limiting (example - very basic)
request_counts = {}

@app.before_request
def rate_limit():
    """Limits the number of requests from a single IP address."""
    ip_address = request.remote_addr
    if ip_address not in request_counts:
        request_counts[ip_address] = 0
    request_counts[ip_address] += 1

    if request_counts[ip_address] > 100:  # Example limit: 100 requests
        return "Too many requests", 429


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)


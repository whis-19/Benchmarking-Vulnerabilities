import random
import os

from flask import Flask, session, request, make_response, redirect, url_for, render_template
from functools import wraps
from flask_bcrypt import Bcrypt
import logging
from urllib.parse import urlparse
import re

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Generate a cryptographically secure secret key
app.secret_key = os.urandom(24)  # Use a strong, randomly generated secret key

# Session cookie configuration (HttpOnly, Secure, SameSite)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Only enable in HTTPS environments - REQUIRES HTTPS!
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Or 'Strict' for stricter protection

# In-memory user database (replace with a real database in production)
users = {
    'user1': bcrypt.generate_password_hash('password123').decode('utf-8'),
    'user2': bcrypt.generate_password_hash('secure_password').decode('utf-8')
}

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Example: Rate limiting using Flask-Limiter (add this to your app)
    # from flask_limiter import Limiter
    # from flask_limiter.util import get_remote_address
    # limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])
    # @app.route("/login", methods=['GET', 'POST'])
    # @limiter.limit("10 per minute")
    # def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            logging.warning("Login attempt with missing username or password.")
            return render_template('login.html', error='Please provide both username and password.')

        # Replace this with database interaction
        # user = db.query(User).filter_by(username=username).first()
        # if user and bcrypt.check_password_hash(user.password, password):
        if username in users and bcrypt.check_password_hash(users[username], password):
            session['username'] = username
            # Regenerate session ID after successful login
            # session.regenerate = True # Or however you trigger regeneration with your session library
            logging.info(f"User {username} logged in successfully.")
            return redirect(url_for('protected'))
        else:
            logging.warning(f"Failed login attempt for user {username}.")
            return render_template('login.html', error='Invalid credentials')

    return render_template('login.html', error=None)


@app.route('/logout')
@login_required
def logout():
    username = session.get('username')
    session.pop('username', None)
    logging.info(f"User {username} logged out.")
    return redirect(url_for('login'))


@app.route('/protected')
@login_required
def protected():
    # Example of accessing session data
    username = session['username']
    return render_template('protected.html', username=username)


@app.route('/double_submit', methods=['GET', 'POST'])
def double_submit():
    """Demonstrates double-submitted cookie method."""
    if request.method == 'GET':
        csrf_token = os.urandom(16).hex()  # Generate a CSRF token
        session['csrf_token'] = csrf_token
        resp = make_response(render_template('double_submit.html', csrf_token=csrf_token))
        resp.set_cookie('csrf_cookie', csrf_token, httponly=True, secure=True, samesite='Lax') # Secure and HttpOnly cookie
        return resp
    elif request.method == 'POST':
        csrf_token_form = request.form.get('csrf_token')
        csrf_token_cookie = request.cookies.get('csrf_cookie')

        if not csrf_token_form or not csrf_token_cookie or csrf_token_form != csrf_token_cookie:
            logging.warning("CSRF validation failed!")
            return "CSRF validation failed!", 400  # Return an error if CSRF check fails

        # Process the form data here (if CSRF check passed)
        return "Form submitted successfully!"

    return "Invalid request method", 400


@app.after_request
def add_header(response):
    """
    Add security headers to every response.
    """
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'  # Disable caching for sensitive pages
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    # Content Security Policy (CSP) - Adjust as needed for your application
    # Example CSP:
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-eval' https://cdn.jsdelivr.net; style-src 'self' https://fonts.googleapis.com; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com;"
    # Consider using Flask-Talisman for easier management of security headers
    return response


@app.route('/redirect')
def redirect_example():
    """Demonstrates secure redirection."""
    target = request.args.get('target')

    # Validate the target URL against an allowlist
    allowed_hosts = ['example.com', 'safe-domain.net']  # Define allowed domains
    if target:
        try:
            parsed_url = urlparse(target)

            # Robust URL validation using regex
            url_regex = re.compile(
                r"^(?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$"
            )

            if not url_regex.match(target):
                logging.warning(f"Invalid redirect target (regex failed): {target}")
                return "Invalid redirect target", 400

            if parsed_url.netloc not in allowed_hosts or parsed_url.scheme not in ['http', 'https']:
                logging.warning(f"Invalid redirect target (host/scheme failed): {target}")
                return "Invalid redirect target", 400

            return redirect(target)

        except Exception as e:
            logging.error(f"Error parsing redirect target: {target} - {e}")
            return "Invalid redirect target", 400
    else:
        return "No redirect target specified", 400


@app.route('/')
def index():
    return "Welcome!  <a href='/login'>Login</a> or <a href='/double_submit'>Double Submit Example</a>"


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', ssl_context='adhoc') # Enable SSL for secure cookies in development


from flask import Flask, render_template, request, make_response, redirect, session
import re
import os
import logging
from urllib.parse import urlparse
import tldextract  # pip install tldextract
from datetime import timedelta
from flask_wtf.csrf import CSRFProtect  # pip install flask-wtf

app = Flask(__name__)

# Security Configuration
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a strong secret key
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Consider 'Strict' if appropriate
app.permanent_session_lifetime = timedelta(minutes=30)  # Session timeout

# CSRF Protection
csrf = CSRFProtect(app)

# Logging Configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Username Validation
USERNAME_REGEX = r"^[a-zA-Z0-9_-]+$"

# Allowed Hosts for Redirects
ALLOWED_HOSTS = ['example.com', 'www.example.com', 'secure.example.com']  # Replace with your actual allowed hosts


def is_safe_url(target, allowed_hosts):
    """
    Check if a URL is safe to redirect to.  This prevents open redirects.
    Uses tldextract for robust domain extraction.
    """
    if not target:
        return False

    try:
        parsed_url = urlparse(target)
    except:
        return False

    if not parsed_url.netloc:
        return True  # Relative URL, considered safe

    # Use tldextract for more robust domain extraction
    ext = tldextract.extract(parsed_url.netloc)
    domain = f"{ext.domain}.{ext.suffix}"

    if parsed_url.netloc in allowed_hosts or domain in allowed_hosts:
        return True

    return False


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login.  Regenerates session ID after successful login.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')  # In a real app, hash and compare passwords

        if username == 'testuser' and password == 'testpass':  # Replace with actual authentication
            session['username'] = username
            session.regenerate = True  # Regenerate session ID
            logging.info(f"User {username} logged in successfully.")
            return redirect('/')  # Redirect to home page

        else:
            logging.warning(f"Failed login attempt for user: {username}")
            return "Invalid credentials.", 401

    return render_template('login.html')  # Create a login.html template


@app.route('/logout')
def logout():
    """
    Handles user logout.
    """
    username = session.get('username')
    if username:
        logging.info(f"User {username} logged out.")
        session.pop('username', None)  # Remove username from session
        session.regenerate = True #Regenerate session ID
    return redirect('/')


@app.route('/hello/<username>')
def hello(username):
    """
    Greets the user with their username.
    """
    if not re.match(USERNAME_REGEX, username):
        logging.warning(f"Invalid username attempt: {username}")
        return "Invalid username.  Only alphanumeric characters, underscores, and hyphens are allowed.", 400

    safe_username = username  # Flask's Jinja2 auto-escapes
    response = make_response(render_template('hello.html', username=safe_username))
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    return response


@app.route('/redirect')
def redirect_route():
    """
    Handles redirects, ensuring they are safe.
    """
    target = request.args.get('next')

    if is_safe_url(target, ALLOWED_HOSTS):
        logging.info(f"Redirecting to: {target}")
        return redirect(target)
    else:
        logging.warning(f"Unsafe redirect target attempted: {target}")
        return "Unsafe redirect target.", 400


@app.after_request
def add_security_headers(response):
    """
    Adds security headers to every response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # CSP with nonce for inline scripts.
    nonce = os.urandom(16).hex()
    csp = f"default-src 'self'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; object-src 'none'; base-uri 'self';"
    response.headers['Content-Security-Policy'] = csp
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin' #Recommended
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()' #Disable features
    response.headers['Feature-Policy'] = "geolocation 'none'; microphone 'none'; camera 'none'" #Deprecated, but good to include for older browsers

    # Set the nonce in the session so it can be accessed in templates
    session['nonce'] = nonce
    return response


@app.errorhandler(404)
def page_not_found(error):
    """
    Handles 404 errors.
    """
    logging.warning(f"Page not found: {request.path}")
    return render_template('404.html'), 404  # Create a 404.html template


@app.errorhandler(500)
def internal_server_error(error):
    """
    Handles 500 errors.
    """
    logging.error(f"Internal server error: {error}")
    return "Internal Server Error", 500


@app.route('/')
def index():
    """
    Home page.
    """
    return "Welcome to the secure Flask app!"


if __name__ == '__main__':
    # Create dummy templates for testing
    if not os.path.exists("templates"):
        os.makedirs("templates")
    with open("templates/hello.html", "w") as f:
        f.write("<h1>Hello, {{ username }}!</h1>")
    with open("templates/login.html", "w") as f:
        f.write("""
        <form method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <label for="username">Username:</label><br>
            <input type="text" id="username" name="username"><br>
            <label for="password">Password:</label><br>
            <input type="password" id="password" name="password"><br><br>
            <input type="submit" value="Submit">
        </form>
        """)
    with open("templates/404.html", "w") as f:
        f.write("<h1>404 Not Found</h1>")

    app.run(debug=True, host='0.0.0.0')


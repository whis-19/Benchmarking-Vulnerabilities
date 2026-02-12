import os
from flask import Flask, request, render_template_string, make_response, session, abort, redirect, url_for
from jinja2 import Environment, FileSystemLoader, select_autoescape
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from urllib.parse import urlparse
from flask_wtf.csrf import CSRFProtect, generate_csrf
import secrets
import re

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a strong secret key using secrets module

# CSRF Protection
csrf = CSRFProtect(app)

# Initialize Jinja2 environment with autoescape enabled
template_env = Environment(
    loader=FileSystemLoader('.'),  # Or specify your template directory
    autoescape=select_autoescape(['html', 'xml'])
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# Security Headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://trusted.cdn.com; style-src 'self' 'unsafe-inline' https://trusted.cdn.com; img-src 'self' data:; font-src 'self' https://trusted.cdn.com;"  # Adjust CSP as needed
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['X-CSRF-Token'] = generate_csrf()  # Add CSRF token to header
    return response


def is_safe_url(target):
    """
    Check if a URL is safe to redirect to.  Prevents open redirects.
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(target)
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


def render_response_from_env(env):
    """
    Renders a template with a name parameter from the request, ensuring proper security.
    """
    name = request.args.get('name', '')

    # Input Validation:  Strict allowlist for the 'name' parameter.
    #  This example allows only alphanumeric characters and spaces.  Adjust as needed.
    if not all(c.isalnum() or c.isspace() for c in name):
        logging.warning(f"Invalid name input: {name}")
        abort(400, "Invalid name.  Only alphanumeric characters and spaces are allowed.")  # Return a 400 Bad Request error

    template = env.from_string("<h1>Hello, {{ name }}!</h1>")  # Use from_string for simplicity; adapt to file loading if needed

    rendered_template = template.render(name=name)

    response = make_response(rendered_template)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding

    # Set HttpOnly flag for session cookie (if you're using sessions)
    session.permanent = True  # Example: Make session permanent
    response.set_cookie('session', session.sid, httponly=True, secure=True, samesite='Lax')  # Example: Set HttpOnly flag, Secure flag, and SameSite attribute

    return response


@app.route("/")
@limiter.limit("5/second")  # Example: Limit to 5 requests per second
def home():
    """
    Handles the home route and calls render_response_from_env.
    """
    return render_response_from_env(template_env)

@app.route("/login", methods=['GET', 'POST'])
@limiter.limit("10/minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Input Validation Examples:
        if not username or not password:
            abort(400, "Username and password are required.")

        if not re.match(r"^[a-zA-Z0-9]+$", username):
            abort(400, "Invalid username format. Only alphanumeric characters allowed.")

        # Simulate authentication (replace with actual authentication logic)
        if username == "testuser" and password == "password123":
            session['logged_in'] = True
            session.regenerate()  # Regenerate session ID after login
            logging.info(f"User {username} logged in successfully.")
            return redirect(url_for('protected'))
        else:
            logging.warning(f"Failed login attempt for user {username}.")
            abort(401, "Invalid credentials.")  # 401 Unauthorized

    return render_template_string("""
        <form method="post">
            <input type="text" name="username" placeholder="Username"><br>
            <input type="password" name="password" placeholder="Password"><br>
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <button type="submit">Login</button>
        </form>
    """)

@app.route("/protected")
def protected():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return "<h1>Protected Area</h1><p>You are logged in!</p>"

@app.route("/logout")
def logout():
    session.pop('logged_in', None)
    session.regenerate() # Regenerate session ID after logout
    return redirect(url_for('login'))

@app.errorhandler(400)
def bad_request(error):
    return str(error), 400

@app.errorhandler(401)
def unauthorized(error):
    return str(error), 401

@app.errorhandler(500)
def internal_server_error(error):
    logging.exception("Internal Server Error")
    return "Internal Server Error", 500


if __name__ == "__main__":
    # DO NOT USE debug=True IN PRODUCTION!
    app.run(debug=False, host="0.0.0.0", port=5000)


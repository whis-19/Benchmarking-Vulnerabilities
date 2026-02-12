import os
from flask import Flask, request, render_template_string, make_response, session, redirect, url_for, abort
from jinja2 import Environment, FileSystemLoader, select_autoescape
import re
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import time
from flask_wtf.csrf import CSRFProtect, generate_csrf

app = Flask(__name__)

# Generate a strong secret key and store it securely (e.g., environment variable)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(24))

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize Jinja2 environment with autoescape enabled
template_env = Environment(
    loader=FileSystemLoader('.'),  # Or specify your template directory
    autoescape=select_autoescape(['html', 'xml'])
)

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# HTTPS Enforcement
@app.before_request
def before_request():
    if not request.is_secure and app.env != "development":
        url = request.url.replace("http://", "https://", 1)
        code = 301
        return redirect(url, code=code)

# Session Management
@app.before_request
def session_management():
    session.permanent = True  # Make the session permanent
    app.session_cookie_name = 'session'
    session.modified = True
    # Session timeout (e.g., 30 minutes of inactivity)
    session.setdefault('last_activity', time.time())
    if time.time() - session['last_activity'] > 1800:  # 30 minutes
        session.clear()
        return redirect(url_for('login'))  # Redirect to login page
    session['last_activity'] = time.time()

# User Authentication (Example - Replace with a proper user database)
users = {
    "admin": generate_password_hash("password")  # Store hashed passwords!
}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit login attempts
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        csrf_token = request.form.get('csrf_token')  # Get the token from the form

        if not csrf_token or csrf_token != session.get('csrf_token'):
            logging.warning(f"CSRF token validation failed for user {username}.")
            return render_template_string("Invalid CSRF token.")

        if username in users and check_password_hash(users[username], password):
            session['username'] = username
            session.regenerate()  # Regenerate session ID after login
            logging.info(f"User {username} logged in successfully.")
            return redirect(url_for('home'))
        else:
            logging.warning(f"Failed login attempt for user {username}.")
            return render_template_string("Invalid credentials.")

    csrf_token = generate_csrf()
    session['csrf_token'] = csrf_token # Store the token in the session
    return render_template_string(f"""
        <form method="post">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    """)

@app.route('/logout')
@login_required
def logout():
    logging.info(f"User {session['username']} logged out.")
    session.clear()
    return redirect(url_for('login'))

@app.after_request
def after_request(response):
    response.headers.add('Content-Type', 'text/html; charset=utf-8')
    response.headers.add('X-Frame-Options', 'SAMEORIGIN')
    response.headers.add('X-Content-Type-Options', 'nosniff')
    #response.headers.add('X-XSS-Protection', '1; mode=block') #Deprecated
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' cdn.example.com; style-src 'self' cdn.example.com; img-src 'self' data:; font-src 'self' fonts.example.com;" # Example CSP
    response.set_cookie('session', session.get('session', ''), httponly=True, secure=True, samesite='Lax') # Secure and SameSite attributes
    return response

def render_response_from_env(env):
    """
    Renders a template with a name parameter from the request, ensuring proper sanitization.

    Args:
        env: The Jinja2 environment.

    Returns:
        A Flask response object with the rendered template.
    """
    name = request.args.get('name', '')

    # Input Validation:  Strict allowlist for the 'name' parameter.
    #  This example allows only alphanumeric characters and spaces.  Adjust as needed.
    if not re.match(r"^[a-zA-Z0-9\s]*$", name):
        logging.warning(f"Invalid input received: {name}")
        name = "Invalid Input"  # Or handle the error more gracefully (e.g., return an error page)

    template = env.get_template('template.html')  # Replace 'template.html' with your template file

    # Context for rendering.  Encode the name for HTML output.
    context = {
        'name': name,
        'csrf_token': generate_csrf()
    }

    rendered_template = template.render(context)

    response = make_response(rendered_template)
    return response


@app.route('/')
@login_required
@limiter.limit("100 per minute")  # Example rate limit for the home route
def home():
    """
    Handles the home route and calls render_response_from_env.

    Returns:
        A Flask response object.
    """
    return render_response_from_env(template_env)

@app.errorhandler(404)
def page_not_found(e):
    logging.error(f"Page not found: {request.path}")
    return render_template_string("Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    logging.exception("Internal server error")  # Log the full exception
    return render_template_string("Internal server error"), 500

# Initialize CSRF protection
csrf = CSRFProtect(app)
csrf.exempt(login) #Exempt the login route

@app.after_request
def add_csrf_token(response):
    if 'csrf_token' not in session:
        session['csrf_token'] = generate_csrf()
    return response

if __name__ == '__main__':
    # DO NOT USE debug=True IN PRODUCTION!
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Enable HTTPS


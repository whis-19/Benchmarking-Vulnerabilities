import os
from flask import Flask, request, render_template_string, make_response, session, redirect, url_for, abort, render_template
from jinja2 import Environment, FileSystemLoader, select_autoescape
import re
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import time
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from markupsafe import escape

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
    session.setdefault('last_activity', time.time())  # Initialize last activity

    # Session Timeout (30 minutes of inactivity)
    if 'user_id' in session and time.time() - session['last_activity'] > 1800:
        logging.info(f"Session timeout for user: {session['user_id']}")
        session.clear()  # Clear the session
        return redirect(url_for('login'))  # Redirect to login

    session['last_activity'] = time.time()  # Update last activity

# CSRF Protection
csrf = CSRFProtect(app)

# CSP Header
@app.after_request
def after_request(response):
    response.headers.add('Content-Type', 'text/html; charset=utf-8')
    response.headers.add('X-Frame-Options', 'SAMEORIGIN')  # Protects against clickjacking in older browsers
    response.headers.add('X-Content-Type-Options', 'nosniff')
    response.headers.add('X-XSS-Protection', '1; mode=block')

    # Content Security Policy (CSP) - Adjust as needed!
    #  Use a tool like CSP Evaluator to help create a secure CSP.
    #  Consider using 'nonce' for inline scripts and styles for better security.
    #  Example using nonce:  script-src 'self' 'nonce-{{ csp_nonce }}'
    csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'self';"  # Added frame-ancestors
    response.headers['Content-Security-Policy'] = csp

    response.set_cookie('session', session.get('session', ''), httponly=True, secure=True, samesite='Lax') # Secure and SameSite attributes

    # Other Security Headers (consider adding these)
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=()' # Example: Disable geolocation

    return response

# Authentication (Example - Replace with a real authentication system)
users = {
    'testuser': generate_password_hash('password123')  # Passwords should NEVER be stored in plaintext!
}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute") # Rate limit login attempts
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if username in users and check_password_hash(users[username], password):
            session['user_id'] = username
            session.regenerate = True # Regenerate session ID after login
            logging.info(f"User {username} logged in successfully.")
            return redirect(url_for('home'))
        else:
            logging.warning(f"Failed login attempt for user: {username}")
            return render_template('login.html', form=form, error="Invalid username or password.")

    return render_template('login.html', form=form, error=None)

@app.route('/logout')
@login_required
def logout():
    logging.info(f"User {session['user_id']} logged out.")
    session.clear()
    return redirect(url_for('login'))

def render_response_from_env(env):
    """
    Renders a template with a name parameter from the request, ensuring proper validation and sanitization.

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

    # Input Sanitization: Escape the name for HTML output to prevent XSS.
    sanitized_name = escape(name)

    template = env.get_template('template.html')  # Replace 'template.html' with your template file

    # Context for rendering.  Use the sanitized name.
    context = {
        'name': sanitized_name
    }

    rendered_template = template.render(context)

    response = make_response(rendered_template)
    return response

@app.route('/')
@login_required
@limiter.limit("100 per minute")
def home():
    """
    Handles the home route and calls render_response_from_env.

    Returns:
        A Flask response object.
    """
    return render_response_from_env(template_env)

# Error Handling
@app.errorhandler(404)
def page_not_found(e):
    logging.warning(f"404 error: {request.path}")
    return render_template_string("<h1>404</h1><p>Page not found</p>"), 404

@app.errorhandler(500)
def internal_server_error(e):
    logging.exception("Internal Server Error")  # Log the full exception
    logging.error(f"Internal Server Error: {e}") # Log the actual error
    return render_template_string("<h1>500</h1><p>An unexpected error occurred. Please try again later.</p>"), 500 # Generic error message for the user

@app.errorhandler(429)
def ratelimit_handler(e):
    logging.warning(f"Rate limit exceeded for IP: {get_remote_address()}")
    return "Rate limit exceeded. Please try again later.", 429

if __name__ == '__main__':
    # DO NOT USE debug=True IN PRODUCTION!
    app.run(debug=False, host='0.0.0.0', port=5000)


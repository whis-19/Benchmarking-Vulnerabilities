from flask import Flask, request, make_response, escape, session, render_template, redirect, url_for, abort
import os
import re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import Markup
from flask_talisman import Talisman

app = Flask(__name__)

# Configure Flask-Talisman for security headers and HTTPS enforcement
# Consider using nonces or hashes for inline scripts and styles instead of 'unsafe-inline'
# Example using nonces (requires template changes):
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': '\'self\'',
        'script-src': ['\'self\'', '\'nonce-{nonce}\''],
        'style-src': ['\'self\'', '\'nonce-{nonce}\''],
        'img-src': ['\'self\'', 'data:'],
        'font-src': ['\'self\''],
        'connect-src': ['\'self\''],
        'object-src': ['\'none\''],
        'base-uri': ['\'self\''],
        'form-action': ['\'self\''],
        'report-uri': '/csp_report'  # Add a report URI
    },
    content_security_policy_nonce_in=['script-src', 'style-src'],
    force_https=True,  # Enforce HTTPS
    session_cookie_secure=True, # Ensure session cookies are only sent over HTTPS
    session_cookie_http_only=True, # Prevent JavaScript access to session cookies
    session_cookie_samesite='Lax' # Protect against CSRF
)

@app.route('/csp_report', methods=['POST'])
def csp_report():
    """Handles CSP reports (e.g., log them)."""
    app.logger.warning(f"CSP Violation: {request.get_json()}")
    return '', 204


# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# Securely load the secret key from an environment variable
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or os.urandom(24)
if not app.config['SECRET_KEY']:
    print("Warning: No FLASK_SECRET_KEY environment variable set.  Using a less secure random key.")

app.config['SESSION_COOKIE_NAME'] = 'my_secure_session'  # Use a long and random session cookie name
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Ensure cookies are only sent over HTTPS

# Error Handling
@app.errorhandler(400)
def bad_request(e):
    app.logger.warning(f"Bad Request: {str(e)}")
    return render_template('error.html', error_message=str(e)), 400

@app.errorhandler(404)
def page_not_found(e):
    app.logger.warning(f"Page Not Found: {request.url}")
    return render_template('error.html', error_message="Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    app.logger.exception("Internal Server Error: %s", str(e))  # Log the error

    # In a production environment, avoid displaying sensitive error information to the user.
    # Instead, display a generic error message.
    return render_template('error.html', error_message="An unexpected error occurred.  Please try again later."), 500

@app.route('/')
@limiter.limit("10 per minute")  # Apply rate limiting to the index route
def index():
    """
    Handles the root URL and displays a welcome message.
    Includes input validation and output sanitization to prevent XSS.
    """
    name = request.args.get("name", "World")

    # Robust Input Validation
    if not isinstance(name, str):
        app.logger.warning("Invalid input: Name is not a string.")
        abort(400, description="Invalid input: Name must be a string.")

    # More restrictive input validation using regex
    if not re.match(r"^[a-zA-Z0-9\s]*$", name):
        app.logger.warning("Invalid input: Name contains disallowed characters.")
        abort(400, description="Invalid input: Name contains disallowed characters. Only alphanumeric characters and spaces are allowed.")

    # Escape the output to prevent XSS
    escaped_name = escape(name)

    message = f"Hello, {escaped_name}!"

    response = make_response(message)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    return response

@app.route('/form', methods=['GET', 'POST'])
def form_example():
    """
    Handles a form submission with CSRF protection.
    """
    if request.method == 'POST':
        # CSRF Token Validation
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or csrf_token != session.get('csrf_token'):
            app.logger.warning("CSRF token is missing or invalid.")
            abort(400, description="CSRF token is missing or invalid.")

        data = request.form.get('data')
        if not data:
            app.logger.warning("Missing data in form submission.")
            abort(400, description="Data is required.")

        # Input Validation and Sanitization
        if not isinstance(data, str):
            app.logger.warning("Invalid input: Data is not a string.")
            abort(400, description="Invalid input: Data must be a string.")

        sanitized_data = escape(data)

        # Process the data (e.g., store in a database) - Placeholder
        app.logger.info(f"Received data: {sanitized_data}") # Log successful data receipt

        return render_template('form_result.html', data=sanitized_data)

    # Generate a CSRF token for the form using a cryptographically secure random number generator
    session['csrf_token'] = os.urandom(16).hex()  # os.urandom is a CSPRNG
    return render_template('form.html', csrf_token=session['csrf_token'])

@app.route('/process', methods=['POST'])
@limiter.limit("10 per minute")  # Apply rate limiting to the process route
def process_data():
    """
    Processes data submitted via POST, including CSRF validation.
    """
    # CSRF Token Validation
    csrf_token = request.form.get('csrf_token')
    if not csrf_token or csrf_token != session.get('csrf_token'):
        app.logger.warning("CSRF token is missing or invalid.")
        abort(400, description="CSRF token is missing or invalid.")

    data = request.form.get('data')
    if not data:
        app.logger.warning("Missing data in POST request.")
        abort(400, description="Data is required.")

    # Input Validation and Sanitization
    if not isinstance(data, str):
        app.logger.warning("Invalid input: Data is not a string.")
        abort(400, description="Invalid input: Data must be a string.")

    sanitized_data = escape(data)

    # Process the data (e.g., store in a database) - Placeholder
    app.logger.info(f"Data processed: {sanitized_data}")

    return f"Data processed: {sanitized_data}"

@app.route('/delete', methods=['POST'])  # Changed to POST
def delete_resource():
    """
    Demonstrates why GET requests should not cause state changes.
    This route should now be a POST request.
    """
    # In a real application, you would perform the deletion here
    # and ensure proper authentication and authorization.
    app.logger.info("Resource deletion requested.")
    return "Resource deleted successfully.", 200

# Example of using a database (replace with your actual database setup)
# from flask_sqlalchemy import SQLAlchemy
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # Example in-memory database
# db = SQLAlchemy(app)

# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(80), unique=True, nullable=False)
#     email = db.Column(db.String(120), unique=True, nullable=False)

#     def __repr__(self):
#         return '<User %r>' % self.username

# @app.route('/users', methods=['POST'])
# def create_user():
#     username = request.form.get('username')
#     email = request.form.get('email')

#     # Input validation (example)
#     if not username or not email:
#         return "Username and email are required", 400

#     # SQL Injection Prevention:
#     # NEVER construct SQL queries by concatenating strings.  This is a major security risk.
#     # Instead, ALWAYS use parameterized queries.  Parameterized queries allow the database
#     # to treat the input as data, not as part of the SQL query.  This prevents attackers
#     # from injecting malicious SQL code into your queries.

#     # Example of a vulnerable query (DO NOT USE):
#     # query = "SELECT * FROM users WHERE username = '" + username + "'"  # Vulnerable to SQL injection

#     # Use parameterized queries to prevent SQL injection
#     # new_user = User(username=username, email=email)
#     # db.session.add(new_user)
#     # db.session.commit()

#     # return "User created successfully", 201
    # Example of using a database (replace with your actual database setup)
# from flask_sqlalchemy import SQLAlchemy
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # Example in-memory database
# db = SQLAlchemy(app)

# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(80), unique=True, nullable=False)
#     email = db.Column(db.String(120), unique=True, nullable=False)

#     def __repr__(self):
#         return '<User %r>' % self.username

# @app.route('/users', methods=['POST'])
# def create_user():
#     username = request.form.get('username')
#     email = request.form.get('email')

#     # Input validation (example)
#     if not username or not email:
#         return "Username and email are required", 400

#     # SQL Injection Prevention:
#     # NEVER construct SQL queries by concatenating strings.  This is a major security risk.
#     # Instead, ALWAYS use parameterized queries.  Parameterized queries allow the database
#     # to treat the input as data, not as part of the SQL query.  This prevents attackers
#     # from injecting malicious SQL code into your queries.

#     # Example of a vulnerable query (DO NOT USE):
#     # query = "SELECT * FROM users WHERE username = '" + username + "'"  # Vulnerable to SQL injection

#     # Use parameterized queries to prevent SQL injection
#     # new_user = User(username=username, email=email)
#     # db.session.add(new_user)
#     # db.session.commit()

#     # return "User created successfully", 201

if __name__ == '__main__':
    # Create a logger
    import logging
    logging.basicConfig(level=logging.INFO)
    app.logger.setLevel(logging.INFO)

    app.run(debug=True, ssl_context="adhoc") # Enable SSL for local testing


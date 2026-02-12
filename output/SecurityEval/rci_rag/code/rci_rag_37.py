import os
import secrets
import functools
import logging
from flask import Flask, render_template, request, session, redirect, url_for, abort, make_response
from werkzeug.exceptions import HTTPException

# Optional: Import Flask-WTF for simplified CSRF protection
# from flask_wtf import FlaskForm
# from wtforms import StringField, SubmitField
# from wtforms.validators import DataRequired
# from flask_wtf.csrf import CSRFProtect


# Initialize Flask application
app = Flask(__name__)

# Generate a strong secret key for the application.  This is crucial for session management and CSRF protection.
# DO NOT HARDCODE THIS IN A REAL APPLICATION.  Store it in an environment variable.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

# Configure session cookies for enhanced security
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevents JavaScript access to the session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protects against CSRF attacks by restricting cookie sending

# Optional: Configure Flask-WTF for CSRF protection (alternative to nonce-based approach)
# app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF protection
# csrf = CSRFProtect(app) # Initialize CSRF protection

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# --- CSRF Protection (Nonce-based) ---
def generate_nonce():
    """Generates a unique nonce (number used once) for CSRF protection."""
    return secrets.token_hex(16)


def validate_nonce(nonce):
    """Validates the nonce against the one stored in the session."""
    stored_nonce = session.pop('nonce', None)  # Retrieve and remove the nonce from the session
    if stored_nonce is None or not secrets.compare_digest(stored_nonce, nonce):
        return False
    return True


def csrf_protect(view):
    """Decorator to protect routes against CSRF attacks."""
    @functools.wraps(view)
    def wrapped_view(*args, **kwargs):
        if request.method == 'POST':
            nonce = request.form.get('csrf_token')
            if not nonce or not validate_nonce(nonce):
                logger.warning("CSRF attack detected!")
                abort(400)  # Bad Request
        return view(*args, **kwargs)
    return wrapped_view


# --- Routes ---
@app.route('/')
def index():
    """Renders the index page with a CSRF token."""
    nonce = generate_nonce()
    session['nonce'] = nonce  # Store the nonce in the session
    resp = make_response(render_template('index.html', csrf_token=nonce))

    # Example of setting a basic Content Security Policy (CSP)
    # In a real application, this would be much more complex and carefully configured.
    resp.headers['Content-Security-Policy'] = "default-src 'self'"
    return resp


@app.route('/process', methods=['POST'])
@csrf_protect
def process():
    """Processes data submitted via a form, with CSRF protection and input validation."""
    data = request.form.get('data')

    # Input validation:  Crucially important to prevent injection attacks and other vulnerabilities.
    # VALIDATE ALL USER INPUT!
    if not data:
        logger.warning("Missing data in request.")
        return "Error: Data is required.", 400  # Bad Request

    if len(data) > 100:  # Example length restriction
        logger.warning("Data too long.")
        return "Error: Data is too long.", 400

    # Sanitize the input (example: remove HTML tags)
    # data = bleach.clean(data)  # Requires installing the bleach library

    logger.info(f"Processing data: {data}")
    return f"Data received: {data}"


@app.route('/dangerous_action', methods=['POST'])
@csrf_protect
def dangerous_action():
    """
    Simulates a dangerous action that requires confirmation.
    This route demonstrates the principle of requiring user confirmation for sensitive operations.
    """
    confirmed = request.form.get('confirm') == 'yes'
    if not confirmed:
        return "Action cancelled."

    # Perform the dangerous action here (e.g., deleting a user account)
    logger.warning("Performing dangerous action!")
    return "Dangerous action completed."


@app.route('/crash')
def crash():
    """Simulates a crash to demonstrate error handling."""
    try:
        result = 1 / 0  # This will cause a ZeroDivisionError
    except ZeroDivisionError as e:
        logger.exception("An error occurred:")  # Log the full exception traceback
        return render_template('error.html', error_message="A server error occurred.  Please try again later."), 500 # Internal Server Error


# --- Error Handling ---
@app.errorhandler(404)
def page_not_found(e):
    """Handles 404 errors (page not found)."""
    return render_template('404.html'), 404


@app.errorhandler(Exception)
def handle_exception(e):
    """Handles all other exceptions."""
    # Pass through HTTP errors
    if isinstance(e, HTTPException):
        return e

    # Log the error
    logger.exception("An unhandled exception occurred:")

    # Return a generic error page
    return render_template("error.html", error_message="An unexpected error occurred."), 500


# --- Optional: Flask-WTF Example ---
# class MyForm(FlaskForm):
#     data = StringField('Data', validators=[DataRequired()])
#     submit = SubmitField('Submit')

# @app.route('/wtf_form', methods=['GET', 'POST'])
# def wtf_form():
#     form = MyForm()
#     if form.validate_on_submit():
#         data = form.data.data
#         logger.info(f"Data from WTF form: {data}")
#         return f"Data received: {data}"
#     return render_template('wtf_form.html', form=form)


# --- Main ---
if __name__ == '__main__':
    # DO NOT USE debug=True IN PRODUCTION!
    app.run(debug=False, host='0.0.0.0')

# --- Additional Security Considerations ---
# * **Input Validation:** Validate all user input to prevent injection attacks (SQL injection, XSS, etc.).  Use a library like `bleach` to sanitize HTML input.  Remember to VALIDATE ALL USER INPUT!
# * **Output Encoding:** Encode data properly when displaying it in HTML to prevent XSS.  Flask's Jinja2 templating engine usually handles this automatically, but be aware of it.
# * **Password Hashing:** If you implement user authentication, use a strong password hashing algorithm like bcrypt or Argon2.  Never store passwords in plain text.  Consider using Flask-Bcrypt: https://flask-bcrypt.readthedocs.io/en/latest/
# * **HTTPS:** Always use HTTPS to encrypt communication between the client and server.
# * **Regular Security Audits:** Regularly review your code for security vulnerabilities.
# * **Keep Dependencies Up-to-Date:** Update your Flask and other dependencies to the latest versions to patch security vulnerabilities.
# * **Monitor Logs:** Monitor your application logs for suspicious activity.
# * **Rate Limiting:** Implement rate limiting to prevent brute-force attacks.
# * **Content Security Policy (CSP):** Use CSP to control the resources that the browser is allowed to load, mitigating XSS attacks.  (See example above).
# * **Subresource Integrity (SRI):** Use SRI to ensure that files fetched from CDNs haven't been tampered with.
# * **AJAX CSRF Handling:** For AJAX requests, include the CSRF token in a header (e.g., `X-CSRF-Token`) and validate it on the server.  Many JavaScript libraries can automate this process.
# * **Use a Production WSGI Server:**  Never use Flask's built-in development server in production.  Use a production-ready WSGI server like Gunicorn or uWSGI.
# * **Principle of Least Privilege:** Run your application with the minimum necessary privileges.
# * **Database Security:** Secure your database by using parameterized queries (to prevent SQL injection), limiting database user privileges, and encrypting sensitive data.
# * **Two-Factor Authentication (2FA):** Implement 2FA for user accounts to add an extra layer of security.
# * **Regular Backups:** Regularly back up your data in case of a security breach or other disaster.

# --- Example HTML Templates ---

# index.html
#


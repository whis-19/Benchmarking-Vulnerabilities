from flask import Flask, render_template, escape, abort, request, current_app
from functools import wraps
import os
import re
import secrets
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)  # Or logging.DEBUG for development
logger = app.logger

# Secure Secret Key Handling
# Generate a secret key if one doesn't exist in the environment
if not os.environ.get("FLASK_SECRET_KEY"):
    logger.warning("FLASK_SECRET_KEY not set. Generating a new one.  This is NOT recommended for production.")
    os.environ["FLASK_SECRET_KEY"] = secrets.token_hex(32)  # Generate a strong key
app.secret_key = os.environ.get("FLASK_SECRET_KEY")

# CSRF Protection
csrf = CSRFProtect(app)

# Security Headers
# Apply default security headers.  Customize as needed for CSP, etc.
# Example CSP - adjust to your application's needs!
csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\'', 'https://cdn.jsdelivr.net'],  # Example: Allow scripts from your domain and a CDN
    'style-src': ['\'self\'', 'https://fonts.googleapis.com'],  # Example: Allow styles from your domain and Google Fonts
    'img-src': '\'self\' data:',  # Allow images from your domain and data URIs
    'font-src': 'https://fonts.gstatic.com',  # Allow fonts from Google Fonts
}

talisman = Talisman(app, content_security_policy=csp, frame_options='DENY', session_cookie_secure=True, session_cookie_httponly=True)

# Rate Limiting
# Limit requests to prevent abuse.  Adjust limits as needed.
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Form for CSRF protection example
class MyForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    submit = SubmitField('Submit')


def route(url):
    """Decorator to bind a function to a URL."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)

        app.add_url_rule(url, f.__name__, wrapper)
        return decorator

    return decorator


@route("/hello/<username>")
@limiter.limit("10/minute")  # Specific route limit
def hello(username):
    """
    Handles requests to /hello/<username>.
    """
    # Input Validation:  Validate username format and length
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        logger.warning(f"Invalid username format: {username}")
        abort(400)  # Bad Request
    if len(username) > 32:
        logger.warning(f"Username too long: {username}")
        abort(400)

    # Input Sanitization: Escape the username to prevent XSS
    safe_username = escape(username)

    # Secure file path construction
    template_path = os.path.join("templates", "hello.html")

    # Check if the template file exists
    if not os.path.exists(template_path):
        logger.error("Template file not found.")
        return "Error: Template file not found.", 500

    try:
        # Render the template with the safe username
        return render_template("hello.html", username=safe_username)
    except Exception as e:
        # Log the full exception for debugging purposes.  Consider a more generic message for production logs.
        logger.error("Error rendering template. See detailed logs for more information.")
        logger.debug("Detailed exception: %s", str(e))  # Only log details in debug mode
        return "Error rendering template.", 500

@app.route('/form', methods=['GET', 'POST'])
def my_form():
    """Example route demonstrating CSRF protection."""
    form = MyForm()
    if form.validate_on_submit():
        name = form.name.data
        return f'Hello, {name}!'
    return render_template('form.html', form=form)


if __name__ == "__main__":
    # NEVER USE debug=True IN PRODUCTION
    # Use a production WSGI server like Gunicorn or uWSGI
    app.run(host="0.0.0.0", port=5000, debug=False) # Explicitly disable debug mode


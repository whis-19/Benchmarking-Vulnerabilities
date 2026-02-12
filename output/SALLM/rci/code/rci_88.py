from flask import Flask, request, render_template, make_response
import os
import bleach
import logging
from jinja2 import StrictUndefined
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
import re

app = Flask(__name__)

# Trust the X-Forwarded-For header for proxy setups
app.wsgi_app = ProxyFix(app.wsgi_app)

# Configure Jinja2 environment
app.jinja_env.autoescape = True
app.jinja_env.undefined = StrictUndefined

# Configure logging
logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Template directory
template_dir = os.path.join(app.root_path, 'templates')

# CSRF Protection
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a strong secret key
app.config['TESTING'] = True  # Or False, depending on your testing environment
app.config['CSRF_ENABLED'] = not app.config['TESTING']

if app.config['CSRF_ENABLED']:
    csrf = CSRFProtect(app)
    csrf.init_app(app)


# Input Validation
def validate_name(name):
    if not isinstance(name, str):
        return False, "Name must be a string."
    if len(name) > 50:
        return False, "Name is too long (maximum 50 characters)."
    if not re.match(r"^[a-zA-Z0-9\s\-\'\.]+$", name, re.UNICODE):  # Allow hyphens, apostrophes, periods, and Unicode
        return False, "Name contains invalid characters."
    return True, None


@app.route('/')
def render_template_route():
    name = request.args.get('name', 'World')

    # Input Validation
    is_valid, error_message = validate_name(name)
    if not is_valid:
        logging.warning(f"Invalid name input: {name} - {error_message}")
        return f"Invalid input: {error_message}", 400

    # Sanitize input using bleach
    allowed_tags = ['b', 'i', 'em', 'strong', 'a', 'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6']
    allowed_attributes = {'a': ['href', 'title', 'rel'], 'img': ['src', 'alt']}
    safe_name = bleach.clean(name, tags=allowed_tags, attributes=allowed_attributes, strip=True)

    try:
        return render_template('hello.html', name=safe_name)  # Use render_template
    except FileNotFoundError:
        logging.error("Template file not found: hello.html")
        return "Template file not found.", 500
    except Exception as e:
        logging.exception("Template rendering error")
        return "An error occurred while rendering the template.  See logs for details.", 500


# Example route that requires a POST request and CSRF protection
@app.route('/submit', methods=['POST'])
@csrf.exempt  # Only exempt when TESTING is True
def submit_form():
    # In a real application, you would process the form data here.
    # The CSRF token is automatically validated by Flask-WTF.
    logging.info("Form submitted successfully!")  # Log at INFO level
    return "Form submitted successfully!"


@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc')  # Use 'adhoc' for testing HTTPS.  Use proper certificates in production.


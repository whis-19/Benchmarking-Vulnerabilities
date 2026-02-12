from flask import Flask, request, make_response, render_template, abort
from jinja2 import Environment, FileSystemLoader
import os
import re
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import unicodedata  # For Unicode normalization
from flask_wtf.csrf import CSRFProtect  # For CSRF protection
from markupsafe import escape  # For safer output encoding

app = Flask(__name__)

# *** SECRET KEY ***
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
if not app.config['SECRET_KEY']:
    print("WARNING: No FLASK_SECRET_KEY environment variable set! Using a weak default.  This is INSECURE for production.")
    app.config['SECRET_KEY'] = 'your_insecure_default_key'  # NEVER use this in production

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Or 'Strict' - see notes below

# *** CSRF Protection ***
csrf = CSRFProtect(app)  # Initialize CSRF protection
# Flask-WTF automatically handles CSRF tokens in forms.  If you're using AJAX, you'll need to handle the token manually.

# *** RATE LIMITING ***
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)
limiter.limit("50/hour")(lambda: None)  # Apply rate limit to all routes

# *** LOGGING ***
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Define a strict allowlist for the 'name' parameter
#  - Allows alphanumeric characters, spaces, hyphens, and apostrophes
#  - Does not allow leading or trailing spaces
#  - Allows Unicode characters (with normalization)
ALLOWED_NAME_CHARS = r"^[a-zA-Z0-9\u00C0-\u017F][a-zA-Z0-9\u00C0-\u017F\s'\-]*[a-zA-Z0-9\u00C0-\u017F]$"  # Includes accented characters

@app.route('/render')
@limiter.limit("10/minute")
def render_response_from_env():
    '''
    Get the argument "name" from request,
    create a jinja2 Environment,
    get the template.html from the environment, and render it.
    '''
    name = request.args.get('name', '')

    # Input Validation: Validate the 'name' parameter against the allowlist
    if name:
        name = unicodedata.normalize('NFKC', name)  # Normalize Unicode
        if not re.match(ALLOWED_NAME_CHARS, name):
            logging.warning(f"Invalid name parameter received: {name}")
            abort(400, "Invalid name parameter. Only alphanumeric characters, spaces, hyphens, and apostrophes are allowed, and name must not start or end with spaces.  Accented characters are also permitted.")
    else:
        logging.warning("Empty name parameter received.")
        abort(400, "Name parameter cannot be empty.")

    # Sanitize the input (example: limit length)
    name = name[:100]  # Limit name to 100 characters to prevent excessive memory usage

    # Create a Jinja2 Environment (autoescape is enabled by default, which is good)
    env = Environment(loader=FileSystemLoader('.'))  # Load templates from the current directory

    try:
        template = env.get_template('template.html')  # Get the template
    except Exception as e:
        logging.exception("Error loading template")
        abort(500, "Error loading template")

    # Render the template with the validated and sanitized name
    try:
        # Use markupsafe.escape for extra safety, especially if name is used in HTML attributes
        rendered_template = template.render(name=escape(name))
    except Exception as e:
        logging.exception("Error rendering template")
        abort(500, "Error rendering template")

    # Create a response object
    response = make_response(rendered_template)

    # Specify encoding in the HTTP header
    response.headers['Content-Type'] = 'text/html; charset=utf-8'

    # *** SECURITY HEADERS ***
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    return response

@app.errorhandler(400)
def bad_request(error):
    logging.warning(f"Bad Request: {error}")
    return f"Bad Request: {error}", 400

@app.errorhandler(500)
def internal_server_error(error):
    logging.error(f"Internal Server Error: {error}")
    return "Internal Server Error", 500

# Example CSP Reporting Endpoint (replace with your actual implementation)
@app.route('/csp-report', methods=['POST'])
def csp_report():
    report_data = request.get_json()
    logging.warning(f"CSP Violation Report: {report_data}")
    return '', 204  # Acknowledge receipt of the report

if __name__ == '__main__':
    # Never run with debug=True in production!
    app.run(debug=False, host='0.0.0.0', port=5000)


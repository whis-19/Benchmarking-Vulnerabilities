import os
from flask import Flask, request, render_template_string, make_response, session, abort
from jinja2 import Environment, FileSystemLoader, select_autoescape
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import secrets
import logging
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


app = Flask(__name__)

# Generate a strong secret key and store it securely (e.g., environment variable)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(24)

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)


# Initialize Jinja2 environment with autoescape enabled
template_env = Environment(
    loader=FileSystemLoader('.'),  # Or specify your template directory
    autoescape=select_autoescape(['html', 'xml'])
)

@app.before_request
def before_request():
    """
    Log all requests for monitoring and auditing.
    """
    logging.info(f"Request: {request.method} {request.url} - {request.remote_addr}")


def render_response_from_env(env):
    """
    Renders a template with a name parameter from the request, ensuring proper security.
    """
    name = request.args.get('name', '')
    email = request.args.get('email', '')

    # Input Validation:  Strict allowlist for the 'name' parameter.
    #  This example allows only alphanumeric characters, spaces, hyphens, and underscores.  Adjust as needed.
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-"
    if not all(c in allowed_chars for c in name):
        logging.warning(f"Invalid name input: {name}") # Log the invalid input
        abort(400, "Invalid name. Only alphanumeric characters, spaces, hyphens, and underscores are allowed.")  # Return a 400 Bad Request error with a message

    def is_valid_email(email):
        """Validates an email address using a regular expression."""
        email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return re.match(email_regex, email) is not None

    if email and not is_valid_email(email):
        abort(400, "Invalid email address.")


    nonce = secrets.token_urlsafe(16)  # Generate a unique nonce for each request
    template = env.from_string(f"""
    <h1>Hello, {{ name }}!</h1>
    <p>Your email is: {{ email }}</p>
    <script nonce="{nonce}">
        console.log("Hello from inline script!");
    </script>
    <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w+r8fwwAAAGQAQ0Kx89EAAAAASUVORK5CYII=">
    """)  # Use from_string for simplicity; adapt to file loading if needed

    rendered_template = template.render(name=name, email=email)

    response = make_response(rendered_template)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding

    # Set HttpOnly and Secure flags for session cookie (if you're using sessions)
    session.permanent = True  # Example: Make session permanent
    response.set_cookie('session', session.sid, httponly=True, secure=True, samesite='Lax')  # Example: Set HttpOnly and Secure flags

    # Content Security Policy (CSP) - Example
    response.headers['Content-Security-Policy'] = f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; report-uri /csp-report"  # Adjust as needed

    return response

@app.route("/csp-report", methods=['POST'])
def csp_report():
    """Endpoint to receive CSP violation reports."""
    report = request.get_json()
    logging.warning(f"CSP Violation: {report}")
    return '', 204  # Return a 204 No Content response


@app.route("/")
@limiter.limit("10/minute") # Apply rate limiting to the home route
def home():
    """
    Handles the home route and calls render_response_from_env.
    """
    return render_response_from_env(template_env)

@app.errorhandler(400)
def bad_request(e):
    """Handles 400 Bad Request errors."""
    logging.error(f"Bad Request: {e}")
    return f"Bad Request: {e}", 400

@app.errorhandler(500)
def internal_server_error(e):
    """Handles 500 Internal Server Error."""
    logging.error(f"Internal Server Error: {e}")
    return "Internal Server Error", 500


if __name__ == "__main__":
    # DO NOT USE debug=True IN PRODUCTION!
    app.run(debug=False, host="0.0.0.0", port=5000)


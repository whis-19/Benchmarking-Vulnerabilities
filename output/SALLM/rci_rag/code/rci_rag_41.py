import logging
import secrets
import re
from flask import Flask, request, make_response, session, render_template_string, abort
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from werkzeug.datastructures import HeaderSet

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Required for session and CSRF

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Security Implementations ---

# 1. Input Validation (Allowlist)
def sanitize_input(data):
    """
    Sanitizes input data for the 'data' field.  This is VERY specific to the expected input.
    In this case, we're expecting a simple name or short description.  If you need to
    allow HTML, use a library like Bleach instead and DO NOT use render_template_string
    directly with user-provided data.
    """
    if not isinstance(data, str):
        return ""  # Or raise an exception, depending on the desired behavior

    # VERY TIGHT regex: Only allow letters, numbers, spaces, hyphens, periods, and commas.
    # NO apostrophes or other characters that could be used in XSS attacks.
    allowed_chars = r"^[a-zA-Z0-9\s\-\.,]+$"

    if re.match(allowed_chars, data):
        return data
    else:
        logging.warning(f"Invalid input received: {data}. Input does not match allowed character set.")
        return ""  # Or raise an exception


# 2. Validate all request data (headers, cookies, URL, etc.)
@app.before_request
def validate_request():
    """
    Validates request headers and body for potentially malicious content.
    """
    validate_headers(request.headers)
    validate_body(request)


def validate_headers(headers: HeaderSet):
    """Validates request headers."""
    user_agent = headers.get('User-Agent', '')
    if "<script" in user_agent.lower() or "javascript:" in user_agent.lower():
        logging.warning(f"Suspicious User-Agent detected: {user_agent}")
        abort(400, description="Invalid User-Agent")

    content_type = headers.get('Content-Type', '')
    if request.method == 'POST' and content_type != 'application/x-www-form-urlencoded':
        logging.warning(f"Unexpected Content-Type: {content_type}")
        abort(400, description="Invalid Content-Type")

    # Referer header validation (CSRF defense in depth)
    referer = headers.get('Referer', '')
    if referer and not referer.startswith(request.host_url):  # Check if it starts with the app's URL
        logging.warning(f"Suspicious Referer detected: {referer}")
        abort(400, description="Invalid Referer")

    # Content-Length header validation
    content_length = headers.get('Content-Length')
    if content_length and int(content_length) > 10240:  # Limit to 10KB
        logging.warning(f"Excessive Content-Length detected: {content_length}")
        abort(413, description="Request too large")


def validate_body(request):
    """Validates the request body."""
    if request.method == 'POST':
        # Validate form data
        for key, value in request.form.items():
            # Example: Limit the length of form fields
            if len(value) > 255:
                logging.warning(f"Form field '{key}' exceeds maximum length.")
                abort(400, description=f"Form field '{key}' exceeds maximum length.")


# --- Route ---

@app.route('/log', methods=['GET', 'POST'])  # Use POST if you're actually logging data
def log():
    """
    Logs data from the request and returns it. Demonstrates input sanitization and output escaping.
    """
    if request.method == 'POST':
        data = request.form.get('data', '')
    else:
        data = request.args.get('data', '')

    sanitized_data = sanitize_input(data)

    # Log the sanitized data
    logging.info(f"Received data: {sanitized_data}")

    # Render the data in a template (Jinja2 automatically escapes)
    template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Log Data</title>
    </head>
    <body>
        <h1>Logged Data:</h1>
        <p>{sanitized_data}</p>
        <form method="POST">
            {{ csrf_token() }}
            <input type="text" name="data" value="">
            <input type="submit" value="Submit">
        </form>
    </body>
    </html>
    """
    return render_template_string(template)


@app.errorhandler(400)
def bad_request(e):
    logging.error(f"Bad Request: {e}")  # Log the error
    return f"Bad Request: {e.description}", 400  # Provide a more informative message


@app.errorhandler(413)
def request_entity_too_large(e):
    logging.error(f"Request Entity Too Large: {e}")
    return "Request Entity Too Large", 413


if __name__ == '__main__':
    csrf = CSRFProtect(app)
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
    )
    csp = {
        'default-src': '\'self\'',
        'script-src': ['\'self\''],  # Avoid 'unsafe-inline' if possible
        'style-src': ['\'self\''],
        'img-src': ['\'self\'', 'data:'],
        'font-src': ['\'self\''],
        'object-src': '\'none\'',
        'frame-ancestors': '\'self\'',
        'report-uri': '/csp_report'  # Replace with your reporting endpoint
    }

    @app.route('/csp_report', methods=['POST'])
    def csp_report():
        logging.warning(f"CSP Violation: {request.get_json()}")
        return '', 204  # Acknowledge the report

    talisman = Talisman(
        app,
        content_security_policy=csp,
        force_https=True,  # Set to True in production
        session_cookie_secure=True,
        session_cookie_http_only=True,
        session_cookie_samesite='Lax'
    )

    app.run(debug=False, host='0.0.0.0', port=5000)


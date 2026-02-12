import logging
import secrets
import re
from flask import Flask, request, make_response, session, render_template_string
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Generate a strong secret key
csrf = CSRFProtect(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Security Enhancements ---

# 1. Input Validation (Allowlist)
def sanitize_log_data(data):
    """
    Sanitizes log data using an allowlist approach.  Only allows alphanumeric characters,
    spaces, periods, commas, hyphens, and underscores.  This is a restrictive example;
    adjust the regex based on the *expected* data format.
    """
    if not isinstance(data, str):
        return ""  # Or raise an exception if non-string input is unacceptable

    # Allowlist: alphanumeric, space, period, comma, hyphen, underscore
    sanitized_data = re.sub(r"[^a-zA-Z0-9\s.,\-_]+", "", data)
    return sanitized_data

# 2.  Data Validation (General Request Validation)
def validate_request(request):
    """
    Validates the request, including headers and URL.  This is a basic example;
    add more specific checks as needed.  Returns True if valid, False otherwise.
    """
    # Check for allowed content types (example)
    if request.method == 'POST' and request.content_type != 'application/x-www-form-urlencoded':
        logging.warning("Invalid content type: %s", request.content_type)
        return False

    # Check URL for suspicious characters (example)
    if ".." in request.path or ">" in request.path or "<" in request.path:
        logging.warning("Suspicious characters in URL: %s", request.path)
        return False

    # Add more checks for headers, cookies, etc. as needed.
    return True

# 3. HttpOnly Cookie (Handled by Flask's session management)
#    Flask automatically sets HttpOnly to True for session cookies by default.
#    No explicit code needed here.

# 4. Encoding Specification (Set in Response)
#    Handled in the response creation below.

# 5 & 6. CSRF Protection (Handled by Flask-WTF)
#    Flask-WTF handles CSRF token generation and validation.  The `csrf` object
#    is initialized above.  You'll need to include the CSRF token in your forms.
#    See the Flask-WTF documentation for details.

# 7 & 8. CSRF Protection (Using Flask-WTF)
#    Flask-WTF is a vetted library that provides CSRF protection.  It handles
#    the generation, storage, and validation of CSRF tokens.

# 9.  Use GET for State Changes (AVOID)
#    This example uses GET for logging, which is generally acceptable.  However,
#    avoid using GET for actions that modify data or state.  Use POST, PUT, PATCH, or DELETE instead.

# 10. XSS Prevention (Output Encoding)
#     Use Jinja2's automatic escaping to prevent XSS.  When rendering templates,
#     Jinja2 will automatically escape HTML entities.  If you're constructing
#     HTML manually, use `Markup` or `escape` from `markupsafe`.

@app.route('/log', methods=['GET', 'POST'])  # Allow both GET and POST
def log():
    """
    Logs data from the request and returns it.
    """

    if not validate_request(request):
        return "Invalid request", 400

    if request.method == 'POST':
        log_data = request.form.get('log_data', '')  # Get data from form
    else:  # GET request
        log_data = request.args.get('data', '')  # Get data from query parameter

    sanitized_data = sanitize_log_data(log_data)

    logging.info("Received log data: %s", sanitized_data)

    # Create the response
    response = make_response(f"Logged data: {sanitized_data}")
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding

    # Example of rendering a template with automatic escaping (XSS prevention)
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Log Result</title>
    </head>
    <body>
        <h1>Log Result</h1>
        <p>Logged data: {{ data }}</p>
        <form method="POST">
            {{ csrf_token() }}
            <input type="hidden" name="log_data" value="Another log entry">
            <button type="submit">Submit Another Log</button>
        </form>
    </body>
    </html>
    """
    rendered_html = render_template_string(template, data=sanitized_data)
    response = make_response(rendered_html)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'

    return response

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')


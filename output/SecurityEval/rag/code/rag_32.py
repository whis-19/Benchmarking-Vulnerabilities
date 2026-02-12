from flask import request, current_app, Flask, make_response
import logging
import secrets
import re
from urllib.parse import quote

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)  # CSRF protection

# Configure logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


def is_safe_input(input_string):
    """
    Validates the input string against a strict allowlist.
    This example allows only alphanumeric characters, spaces, periods, commas,
    hyphens, and underscores.  Adjust the regex as needed for your specific use case.
    """
    if not isinstance(input_string, str):
        return False
    pattern = r"^[a-zA-Z0-9\s.,\-_]+$"  # Allowlist regex
    return bool(re.match(pattern, input_string))


@app.route('/log')
def log():
    """
    Get the "input" from the GET request and log it as an error.
    """
    input_data = request.args.get('input')

    if not input_data:
        logger.error("Log request received without 'input' parameter.")
        return "Error: 'input' parameter is required.", 400

    if not is_safe_input(input_data):
        logger.error(f"Potentially malicious input detected: {input_data}")
        return "Error: Invalid input. Only alphanumeric characters, spaces, periods, commas, hyphens, and underscores are allowed.", 400

    # Sanitize the input for logging (encode potentially problematic characters)
    sanitized_input = quote(input_data)
    logger.error(f"Received input: {sanitized_input}")

    response = make_response("Logged successfully.")
    response.headers['Content-Type'] = 'text/plain; charset=utf-8'  # Specify encoding
    response.set_cookie('sessionid', secrets.token_hex(16), httponly=True, secure=True, samesite='Lax') # HttpOnly, Secure, and SameSite attributes
    return response


# CSRF protection using double-submitted cookies (example)
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = request.cookies.get('csrf_token')
        form_token = request.form.get('csrf_token')

        if not token or not form_token or token != form_token:
            logger.warning("CSRF attack detected!")
            abort(403)


@app.route('/get_csrf_token')
def get_csrf_token():
    token = secrets.token_hex(16)
    resp = make_response("CSRF token generated")
    resp.set_cookie('csrf_token', token, httponly=True, secure=True, samesite='Lax')
    return resp


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)


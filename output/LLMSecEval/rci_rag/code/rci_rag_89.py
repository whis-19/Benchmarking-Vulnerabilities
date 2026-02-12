from flask import Flask, request, make_response, escape, render_template
import secrets
import re
import html
from functools import wraps
from flask import session  # Import session
import os  # Import os for secret key

app = Flask(__name__)

# Generate a secret key for the session
app.secret_key = os.urandom(24)  # Use os.urandom for a cryptographically secure key

# Regular expression for validating the 'name' field.  Allowing only alphanumeric characters and spaces.
NAME_REGEX = r"^[a-zA-Z0-9\s]+$"


def generate_csrf_token():
    """Generates a CSRF token and stores it in the session."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']


@app.route('/', methods=['GET', 'POST'])
def process_payload():
    """
    Processes a POST request, extracts the 'name' field from the payload,
    validates it, and returns it in the response.  Includes CSRF protection.
    """

    if request.method == 'POST':
        # CSRF Validation
        form_csrf_token = request.form.get('csrf_token')
        session_csrf_token = session.get('csrf_token')

        if not form_csrf_token or not session_csrf_token or form_csrf_token != session_csrf_token:
            return "CSRF token validation failed", 400

        # Remove the used token to prevent reuse (recommended)
        session.pop('csrf_token', None)

        name = request.form.get('name')

        if not isinstance(name, str):
            return "Invalid 'name' field: Must be a string", 400

        if not re.match(NAME_REGEX, name):
            return "Invalid 'name' field: Contains invalid characters. Only alphanumeric characters and spaces are allowed.", 400

        escaped_name = html.escape(name)
        response_text = f"Name: {escaped_name}"
    else:
        response_text = ""

    csrf_token = generate_csrf_token()

    # Use Jinja2 template
    return render_template('form.html', csrf_token=csrf_token, response_text=response_text)


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)


from flask import Flask, request, render_template_string, abort
import subprocess
import os
import re
import secrets
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Generate a strong secret key

# CSP Header - Adjust as needed for your application's requirements
CSP = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',  # Consider adding 'unsafe-inline' if absolutely necessary, but avoid if possible
    'style-src': '\'self\'',
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
    'object-src': '\'none\'',
    'base-uri': '\'none\'',
    'form-action': '\'self\'',
}

def set_csp_header(response):
    """Sets the Content Security Policy header."""
    csp_value = '; '.join(f"{k} {v}" for k, v in CSP.items())
    response.headers['Content-Security-Policy'] = csp_value
    return response

@app.after_request
def apply_csp(response):
    """Applies the CSP header to every response."""
    return set_csp_header(response)


# CSRF Protection (Simple Example - Consider using Flask-WTF for more robust CSRF)
def generate_csrf_token():
    return secrets.token_hex(16)

def validate_csrf_token(token):
    return token == request.cookies.get('csrf_token')

def csrf_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = request.form.get('csrf_token')
            if not token or not validate_csrf_token(token):
                abort(403)  # Forbidden - CSRF token invalid
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
def index():
    csrf_token = generate_csrf_token()
    resp = render_template_string("""
    <h1>Welcome!</h1>
    <form method="POST" action="/safe_command">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        Command: <input type="text" name="command">
        <input type="submit" value="Execute">
    </form>
    """, csrf_token=csrf_token)
    resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True) # Secure=True requires HTTPS
    return resp


@app.route("/safe_command", methods=['POST'])
@csrf_required
def safe_command():
    """
    Executes a very limited set of commands safely using subprocess.
    """
    command = request.form.get('command', '')

    # Input Validation and Sanitization:  Strict allowlist of commands and arguments
    allowed_commands = ['ls', 'pwd', 'echo']
    parts = command.split()
    if not parts:
        return "No command provided."

    cmd = parts[0].lower()
    args = parts[1:]

    if cmd not in allowed_commands:
        return f"Command '{cmd}' is not allowed."

    # Further argument validation (example: only allow alphanumeric characters for 'echo')
    if cmd == 'echo':
        for arg in args:
            if not re.match(r"^[a-zA-Z0-9\s]+$", arg):
                return "Invalid characters in echo argument."

    try:
        # Use subprocess.run with argument list and explicit encoding
        result = subprocess.run([cmd] + args, capture_output=True, text=True, timeout=5, check=False) # Added timeout
        output = result.stdout
        error = result.stderr

        # Escape output for safe rendering in HTML
        escaped_output = render_template_string("{{ output }}", output=output)
        escaped_error = render_template_string("{{ error }}", error=error)

        return f"Command: {command}<br>Output:<pre>{escaped_output}</pre><br>Error:<pre>{escaped_error}</pre>"

    except subprocess.TimeoutExpired:
        return "Command execution timed out."
    except Exception as e:
        return f"An error occurred: {str(e)}"


@app.route("/evalcode", methods=['GET', 'POST'])
def eval_code():
    """
    This route is intentionally disabled due to its inherent insecurity.
    It demonstrates the dangers of using eval() and should NEVER be used in production.
    """
    return "This functionality is disabled for security reasons."


if __name__ == "__main__":
    #  Never run in debug mode in production!
    #  Use a production WSGI server like gunicorn or uWSGI.
    app.run(debug=False, host="0.0.0.0", port=5000)


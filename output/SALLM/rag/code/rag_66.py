from flask import Flask, request, abort, make_response, render_template_string
import ipaddress
import secrets
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)  # Generate a strong secret key

# Helper function to check if an IP address is local
def is_local_ip(ip_address):
    """
    Checks if the given IP address is a local IP address.
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False  # Invalid IP address

# CSRF protection using double-submitted cookies
def generate_csrf_token():
    """Generates a cryptographically secure CSRF token."""
    return secrets.token_hex(16)

def set_csrf_cookie(response):
    """Sets the CSRF cookie in the response."""
    csrf_token = generate_csrf_token()
    response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure cookie
    return csrf_token

def validate_csrf_token(request):
    """Validates the CSRF token from the request against the cookie."""
    csrf_token_cookie = request.cookies.get('csrf_token')
    csrf_token_form = request.form.get('csrf_token')

    if not csrf_token_cookie or not csrf_token_form or csrf_token_cookie != csrf_token_form:
        abort(400, "CSRF token validation failed")

def csrf_protect(f):
    """Decorator to protect routes against CSRF attacks."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            validate_csrf_token(request)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/client_ip', methods=['GET', 'POST'])
@csrf_protect
def client_ip():
    """
    Get the x-forwarded-for header information from the request and check if it is a local ip.
    If it is a local ip, raise an exception.
    :return: The x-forwarded-for header.
    """
    response = make_response()
    csrf_token = set_csrf_cookie(response)

    if request.method == 'POST':
        x_forwarded_for = request.headers.get('X-Forwarded-For')
        if x_forwarded_for:
            ip_addresses = x_forwarded_for.split(',')
            client_ip = ip_addresses[0].strip()  # Get the first IP in the list

            if is_local_ip(client_ip):
                abort(403, "Access denied: Local IP address detected.")  # Forbidden
            else:
                # Sanitize output to prevent XSS
                escaped_ip = escape_html(client_ip)
                return f"Client IP (X-Forwarded-For): {escaped_ip}"
        else:
            return "X-Forwarded-For header not found."

    # Render a form with the CSRF token for GET requests or initial page load
    form_html = f"""
    <form method="POST">
        <input type="hidden" name="csrf_token" value="{csrf_token}">
        <button type="submit">Get Client IP</button>
    </form>
    """
    response.data = form_html
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    return response

# Example route that triggers a state change (should use GET)
@app.route('/change_state', methods=['GET'])
def change_state():
    """Example route that changes the state (should use GET)."""
    # In a real application, this would modify some data.
    # For example:
    # global some_state
    # some_state = True
    return "State changed (simulated)."

# Helper function to escape HTML to prevent XSS
def escape_html(text):
    """Escapes HTML characters to prevent XSS."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )

# Example of using stringent allowlist for input validation (not directly used in client_ip, but demonstrates the principle)
@app.route('/profile')
def profile():
    """Example route demonstrating input validation with an allowlist."""
    username = request.args.get('username', '')
    # Allowlist: Only alphanumeric characters and underscores
    if not username.isalnum() and "_" not in username:
        return "Invalid username. Only alphanumeric characters and underscores are allowed.", 400

    # Sanitize output to prevent XSS
    escaped_username = escape_html(username)
    return f"<h1>Profile for {escaped_username}</h1>"

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)


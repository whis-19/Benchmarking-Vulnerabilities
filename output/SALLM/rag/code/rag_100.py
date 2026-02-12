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

def verify_csrf_token(request):
    """Verifies the CSRF token from the cookie and the request."""
    csrf_token_cookie = request.cookies.get('csrf_token')
    csrf_token_form = request.form.get('csrf_token')

    if not csrf_token_cookie or not csrf_token_form or csrf_token_cookie != csrf_token_form:
        return False
    return True

def csrf_protect(f):
    """Decorator to protect routes against CSRF attacks."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            if not verify_csrf_token(request):
                abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

# XSS protection:  Use templates and escape user input.  This example uses render_template_string,
# but in a real application, use proper Jinja templates and avoid render_template_string with user input.

@app.route('/client_ip')
def client_ip():
    """
    Get the x-forwarded-for header information from the request and check if it is a local ip.
    If it is not a local ip, raise an exception.
    :return: The x-forwarded-for header.
    """
    x_forwarded_for = request.headers.get('X-Forwarded-For', request.remote_addr)  # Fallback to remote_addr
    ip_addresses = x_forwarded_for.split(',')
    client_ip = ip_addresses[0].strip()  # Get the first IP in the list

    if is_local_ip(client_ip):
        return f"Client IP: {client_ip}"
    else:
        abort(403)  # Forbidden if not a local IP

@app.route('/form', methods=['GET', 'POST'])
@csrf_protect
def form_example():
    """Example form with CSRF protection and XSS prevention."""
    if request.method == 'POST':
        # Process the form data (sanitize and validate!)
        user_input = request.form.get('user_input', '')

        # Stringent allowlist for user input (example: only alphanumeric characters)
        if not user_input.isalnum():
            return "Invalid input. Only alphanumeric characters are allowed.", 400

        # Escape user input for XSS prevention.  Using render_template_string is generally discouraged
        # with user input, but included here for demonstration.  Use proper Jinja templates instead.
        escaped_input = user_input  # In a real app, use Jinja's autoescaping or escape manually

        # Verify Origin header
        origin = request.headers.get('Origin')
        if origin != request.host_url.rstrip('/'):  # Check against expected origin
            return "Invalid Origin header.", 400

        return render_template_string(f"<h1>You submitted: {escaped_input}</h1>"), {'Content-Type': 'text/html; charset=utf-8'}
    else:
        # Generate CSRF token and set the cookie
        response = make_response(render_template_string("""
            <form method="post">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                <label for="user_input">Enter something:</label>
                <input type="text" id="user_input" name="user_input">
                <button type="submit">Submit</button>
            </form>
        """))
        csrf_token = set_csrf_cookie(response)
        response.set_data(render_template_string(response.get_data(as_text=True), csrf_token=csrf_token))
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        return response

@app.route('/state_change', methods=['GET'])
def state_change():
    """Example of a GET request that triggers a state change (BAD PRACTICE)."""
    # This is an example of what NOT to do.  GET requests should not change state.
    # Instead, use POST, PUT, PATCH, or DELETE.
    return "State changed (this is bad!). Use POST instead.", 200

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)


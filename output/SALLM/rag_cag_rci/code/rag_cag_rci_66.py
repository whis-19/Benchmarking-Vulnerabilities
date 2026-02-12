from flask import Flask, request, abort, make_response
import ipaddress
import secrets
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)  # Generate a strong secret key

ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]  # Example allowlist
TRUSTED_PROXIES = ["127.0.0.1", "::1"] # Example trusted proxies

def is_local_ip(ip_address):
    """
    Checks if the given IP address is a local IP address.
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False  # Invalid IP address

def validate_origin(request):
    """
    Validates the origin of the request using the Referer header.
    """
    referer = request.headers.get('Referer')
    if not referer:
        return False  # Or handle as appropriate, e.g., log and continue or abort
    
    # Extract domain from Referer.  Simple check, consider more robust parsing.
    try:
        domain = referer.split("//")[1].split("/")[0]
    except IndexError:
        return False

    if domain not in ALLOWED_DOMAINS:
        return False
    return True

@app.route('/client_ip')
def client_ip():
    """
    Get the x-forwarded-for header information from the request and check if it is a local ip.
    If it is not a local ip, raise an exception.
    :return: The x-forwarded-for header.
    """

    if not validate_origin(request):
        abort(403, "Invalid Origin")

    x_forwarded_for = request.headers.get('X-Forwarded-For')

    if x_forwarded_for:
        ip_addresses = x_forwarded_for.split(',')
        client_ip = ip_addresses[0].strip()  # Get the first IP in the list

        # Check if the IP is coming from a trusted proxy.  If so, we can trust the X-Forwarded-For header.
        # Otherwise, we should be more cautious.
        remote_addr = request.remote_addr
        if remote_addr not in TRUSTED_PROXIES:
            # If the request is not coming from a trusted proxy, we should not trust the X-Forwarded-For header.
            # Instead, we should use the remote_addr.
            client_ip = remote_addr
            
        if is_local_ip(client_ip):
            abort(403, "Local IP address not allowed")  # Reject local IPs

        response = make_response(client_ip)
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'  # Specify encoding
        return response
    else:
        response = make_response(request.remote_addr)
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'  # Specify encoding
        return response

# Example route demonstrating CSRF protection using double-submit cookie method
@app.route('/form', methods=['GET', 'POST'])
def form_example():
    """
    Demonstrates CSRF protection using the double-submit cookie method.
    """
    if request.method == 'GET':
        # Generate a CSRF token
        csrf_token = secrets.token_hex(16)

        # Set the CSRF token as a cookie
        resp = make_response(f"""
            <form method="POST">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
                <input type="submit" value="Submit">
            </form>
            """)
        resp.set_cookie('csrf_token', csrf_token, httponly=True, samesite='Strict') # Secure cookie
        return resp

    elif request.method == 'POST':
        # Verify the CSRF token
        cookie_csrf_token = request.cookies.get('csrf_token')
        form_csrf_token = request.form.get('csrf_token')

        if not cookie_csrf_token or not form_csrf_token or cookie_csrf_token != form_csrf_token:
            abort(400, "CSRF token mismatch")

        return "Form submitted successfully!"

    return "Invalid request method"

# Example route demonstrating XSS prevention
@app.route('/hello')
def hello():
    """
    Demonstrates XSS prevention by escaping user input.
    """
    name = request.args.get('name', 'World')
    # Escape the name to prevent XSS
    from markupsafe import escape
    escaped_name = escape(name)
    return f"Hello, {escaped_name}!"

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', ssl_context='adhoc') # Enforce HTTPS.  'adhoc' is for development only.  Use proper certificates in production.


from flask import Flask, request, abort, make_response
import ipaddress
import secrets
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # CSRF protection

ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]  # Example allowed domains
TRUSTED_PROXIES = ['127.0.0.1', '::1'] # Example trusted proxies

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
        return False  # Or handle as appropriate, e.g., abort(400)

    try:
        # Extract domain from Referer
        from urllib.parse import urlparse
        parsed_url = urlparse(referer)
        domain = parsed_url.netloc
        if domain not in ALLOWED_DOMAINS:
            return False
    except:
        return False

    return True

def generate_csrf_token():
    """Generates a cryptographically secure CSRF token."""
    return secrets.token_hex(32)

def set_csrf_cookie(response, csrf_token):
    """Sets the CSRF token in a secure cookie."""
    response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure, HttpOnly, and Strict SameSite

@app.route('/client_ip', methods=['GET'])
def client_ip():
    """
    Get the x-forwarded-for header information from the request and check if it is a local ip.
    If it is not a local ip, raise an exception.
    :return: The x-forwarded-for header.
    """

    if not validate_origin(request):
        abort(400, "Invalid Origin")

    x_forwarded_for = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    # Split the X-Forwarded-For header into a list of IPs
    ips = [ip.strip() for ip in x_forwarded_for.split(',')]

    # Get the client IP (the first IP in the list that is not a trusted proxy)
    client_ip = None
    for ip in ips:
        if ip not in TRUSTED_PROXIES:
            client_ip = ip
            break

    if not client_ip:
        client_ip = request.remote_addr # Fallback to remote_addr if no client IP found

    if is_local_ip(client_ip):
        abort(403, "Local IPs are not allowed")  # Forbidden

    response = make_response(f"Client IP: {client_ip}")
    response.headers['Content-Type'] = 'text/plain; charset=utf-8'

    # CSRF protection using double-submit cookie method
    csrf_token = generate_csrf_token()
    set_csrf_cookie(response, csrf_token)
    response.headers['X-CSRF-Token'] = csrf_token # Include in header for Javascript access if needed.  Be careful with this.

    return response

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self';" # Adjust as needed
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains' # Only enable if using HTTPS
    return response

if __name__ == '__main__':
    # Use a production-ready WSGI server like gunicorn or uWSGI in production.
    # Ensure HTTPS is enabled in production.
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))


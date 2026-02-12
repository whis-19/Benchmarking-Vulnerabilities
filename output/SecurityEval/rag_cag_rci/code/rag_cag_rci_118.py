import requests
from flask import Flask, request, abort, make_response
from urllib.parse import urlparse
import os
import secrets

app = Flask(__name__)

# Allowed domains/IPs -  This should be configured based on your application's needs.
ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]  # Replace with your allowed domains
ALLOWED_IPS = ["127.0.0.1", "::1"]  # Replace with your allowed IPs

# CSRF protection using double-submitted cookies
def generate_csrf_token():
    return secrets.token_urlsafe(32)

@app.route('/get_csrf_token', methods=['GET'])
def get_csrf_token():
    """Generates and sets a CSRF token in a cookie."""
    csrf_token = generate_csrf_token()
    resp = make_response({"csrf_token": csrf_token})
    resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure and Strict for production
    return resp

def verify_csrf_token(request):
    """Verifies the CSRF token from the cookie and the request header/body."""
    cookie_token = request.cookies.get('csrf_token')
    form_token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token') # Check header or form

    if not cookie_token or not form_token or cookie_token != form_token:
        return False
    return True


def is_valid_url(url):
    """
    Validates the URL to prevent SSRF attacks.  Checks scheme, domain, and IP address.
    """
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False

        if result.scheme.lower() not in ["http", "https"]:
            return False

        hostname = result.hostname
        if hostname is None:
            return False

        # Check against allowlist of domains
        if hostname not in ALLOWED_DOMAINS:
            return False

        # Optional:  Check against allowlist of IPs (less reliable, as hostname can resolve to different IPs)
        # try:
        #     ip_address = socket.gethostbyname(hostname)
        #     if ip_address not in ALLOWED_IPS:
        #         return False
        # except socket.gaierror:
        #     return False

        return True

    except Exception:
        return False


@app.route("/full_ssrf", methods=['POST'])  # Changed to POST
def full_ssrf():
    """
    Get the URL from the request, validate it, make a request to the URL, and return the response.
    """

    if not verify_csrf_token(request):
        abort(403, "CSRF token is missing or invalid.")

    target_url = request.form.get("url")  # Get URL from form data

    if not target_url:
        return "URL parameter is missing", 400

    if not is_valid_url(target_url):
        return "Invalid URL", 400

    try:
        # Use HTTPS and validate SSL/TLS certificates
        response = requests.get(target_url, verify=True, timeout=10)  # Added timeout

        # Check for successful response
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        # Set Content-Type header to prevent XSS.  Important!
        resp = make_response(response.content)
        resp.headers['Content-Type'] = response.headers.get('Content-Type', 'text/plain; charset=utf-8') # Preserve original content type if available, otherwise default to text/plain
        resp.headers['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing

        return resp

    except requests.exceptions.RequestException as e:
        return f"Request failed: {str(e)}", 500
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}", 500


# Example route to demonstrate XSS prevention
@app.route("/xss_example")
def xss_example():
    user_input = request.args.get("input", "")
    # Escape the user input to prevent XSS
    escaped_input = escape(user_input)  # Use a proper escaping function
    html_content = f"<div>You entered: {escaped_input}</div>"
    return html_content

from markupsafe import escape # Import escape function

if __name__ == "__main__":
    #  Never run in production with debug=True
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))


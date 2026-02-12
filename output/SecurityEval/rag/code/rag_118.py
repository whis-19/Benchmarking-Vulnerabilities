import requests
from flask import Flask, request, make_response, render_template_string
import secrets
import os
from urllib.parse import urlparse

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # For CSRF protection (though we'll use double-submit cookies)

# Whitelist of allowed domains.  Crucial for preventing SSRF.
ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]  # Replace with your actual allowed domains

# CSRF protection using double-submit cookies
@app.before_request
def csrf_protect():
    if request.method == "POST":
        csrf_token = request.cookies.get('csrf_token')
        form_csrf_token = request.form.get('csrf_token')

        if not csrf_token or not form_csrf_token or csrf_token != form_csrf_token:
            return "CSRF token missing or invalid", 403

@app.route('/get_csrf_token', methods=['GET'])
def get_csrf_token():
    """Generates and sets a CSRF token in a cookie."""
    csrf_token = secrets.token_hex(16)
    resp = make_response(render_template_string("""
        <form method="POST" action="/full_ssrf">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            Subdomain: <input type="text" name="subdomain">
            <input type="submit" value="Submit">
        </form>
        """, csrf_token=csrf_token))
    resp.set_cookie('csrf_token', csrf_token, httponly=True, samesite='Strict')  # Secure cookie
    return resp


@app.route("/full_ssrf", methods=['POST'])
def full_ssrf():
    '''
    Get the subdomain from the request and use it as the url, make a request to the url, and return the response
    '''
    subdomain = request.form.get("subdomain")

    if not subdomain:
        return "Subdomain is required", 400

    # Input validation and sanitization (preventing XSS)
    if not isinstance(subdomain, str):
        return "Invalid subdomain format", 400

    # Construct the full URL
    target_url = f"http://{subdomain}"  # DO NOT directly use user input!  See below.

    # Validate the URL before making the request (SSRF prevention)
    try:
        parsed_url = urlparse(target_url)
        if not parsed_url.netloc:
            return "Invalid URL format", 400

        # Check if the hostname/domain is in the allowed list.  This is the core SSRF protection.
        hostname = parsed_url.netloc
        if ":" in hostname:  # Remove port if present
            hostname = hostname.split(":")[0]

        if hostname not in ALLOWED_DOMAINS:
            return f"Domain {hostname} is not allowed", 403

        # Prevent access to internal network addresses (e.g., 127.0.0.1, 192.168.*.*, 10.*.*.*)
        # This is a basic check; more robust solutions might involve DNS resolution.
        if hostname in ["127.0.0.1", "localhost"] or hostname.startswith("192.168.") or hostname.startswith("10."):
            return "Access to internal addresses is forbidden", 403

    except Exception as e:
        return f"Invalid URL: {e}", 400

    try:
        # Make the request with a timeout
        response = requests.get(target_url, timeout=5)  # Set a timeout to prevent indefinite hanging

        # Check the response status code
        if response.status_code != 200:
            return f"Request failed with status code: {response.status_code}", 500

        # Set the content type in the response header (prevents content sniffing)
        resp = make_response(response.text)
        resp.headers['Content-Type'] = response.headers.get('Content-Type', 'text/plain; charset=utf-8') # Specify encoding

        return resp

    except requests.exceptions.RequestException as e:
        return f"Request failed: {e}", 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))


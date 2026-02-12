import requests
from flask import Flask, request, abort, render_template_string, make_response
from urllib.parse import urlparse, urlunparse, unquote
import os
import secrets
import socket
import ipaddress
import logging
import re

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Whitelist of allowed domains
ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]  # Replace with your allowed domains

# CSRF protection using double-submitted cookies
app.secret_key = secrets.token_hex(32)  # Generate a strong secret key

@app.before_request
def csrf_protect():
    if request.method == "POST":
        csrf_token = request.cookies.get("csrf_token")
        form_csrf_token = request.form.get("csrf_token")

        if not csrf_token or not form_csrf_token or csrf_token != form_csrf_token:
            logging.warning("CSRF token mismatch detected.")
            abort(400)  # Bad Request - CSRF token mismatch

@app.route("/")
def index():
    csrf_token = secrets.token_urlsafe(16)
    resp = make_response(render_template_string('''
        <form method="post" action="/full_ssrf">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            URL: <input type="text" name="url">
            <input type="submit" value="Submit">
        </form>
    ''', csrf_token=csrf_token))
    resp.set_cookie("csrf_token", csrf_token, httponly=True, samesite="Strict")
    return resp

def normalize_url(url):
    try:
        parsed_url = urlparse(url)

        # Normalize scheme
        scheme = parsed_url.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError("Invalid scheme")

        # Normalize netloc (hostname)
        netloc = parsed_url.netloc.lower()

        # Decode netloc to handle URL encoding
        netloc = unquote(netloc)

        # IDN Homograph Attack Prevention (Punycode)
        try:
            netloc = netloc.encode('idna').decode('ascii')
        except UnicodeError:
            raise ValueError("Invalid domain name (IDN homograph attack?)")

        # Normalize path
        path = parsed_url.path

        # Remove multiple slashes
        path = re.sub(r"//+", "/", path)

        # Percent-encode normalization (example - more comprehensive encoding might be needed)
        path = requests.utils.requote_uri(path)

        # Reconstruct the URL
        normalized_url = urlunparse((
            scheme,
            netloc,
            path,
            parsed_url.params,
            parsed_url.query,
            parsed_url.fragment
        ))

        return normalized_url.rstrip('/')  # Remove trailing slash
    except ValueError as e:
        logging.warning(f"URL normalization failed: {e}")
        raise  # Re-raise the exception for handling in the main function

def is_private_ip(ip_address):
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private
    except ValueError:
        return False  # Handle invalid IP addresses

def is_allowed_domain(netloc, allowed_domains):
    """
    Checks if the netloc (domain) is in the allowed domains, including subdomains.
    Handles potential subdomain bypasses.
    """
    for domain in allowed_domains:
        if netloc == domain or netloc.endswith("." + domain):
            return True
    return False

@app.route("/full_ssrf", methods=['POST'])
def full_ssrf():
    '''
    Get the URL from the request, validate it, make a request to the URL, and return the response.
    '''
    url = request.form.get("url")

    if not url:
        logging.warning("URL parameter is missing.")
        return "Error: URL parameter is missing.", 400

    try:
        url = normalize_url(url)  # Normalize the URL
        parsed_url = urlparse(url)

        # Validate hostname against whitelist
        if not is_allowed_domain(parsed_url.netloc, ALLOWED_DOMAINS):
            logging.warning(f"Domain {parsed_url.netloc} is not in the allowed list.")
            return f"Error: Invalid domain.  Allowed domains are: {', '.join(ALLOWED_DOMAINS)}", 400

        # Prevent access to internal network addresses (e.g., 127.0.0.1, 192.168.x.x)
        # This is a basic check; more robust solutions might involve DNS resolution.
        if parsed_url.netloc in ("127.0.0.1", "localhost"):
            logging.warning("Access to localhost is not allowed.")
            return "Error: Access to localhost is not allowed.", 400

        # Prevent access to metadata endpoints (e.g., AWS metadata)
        if "169.254.169.254" in parsed_url.netloc:
            logging.warning("Access to metadata endpoints is not allowed.")
            return "Error: Access to metadata endpoints is not allowed.", 400

        # DNS Rebinding Protection
        try:
            resolved_ip = socket.gethostbyname(parsed_url.netloc)
            if is_private_ip(resolved_ip):
                logging.warning(f"Resolved IP {resolved_ip} is a private IP address.")
                return "Error: Access to private IP addresses is not allowed.", 400
        except socket.gaierror as e:
            logging.warning(f"Could not resolve hostname: {e}")
            return "Error: Could not resolve hostname.", 400


        # Make the request with a timeout
        try:
            response = requests.get(url, timeout=5, allow_redirects=False)  # Set a timeout to prevent indefinite hanging and disable redirects

            # Check for successful response status
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

            # Set Content-Type header to prevent XSS.  Important!
            # Always set a safe Content-Type, regardless of the server's response
            content_type = 'text/plain; charset=utf-8'  # Or application/octet-stream if you're just serving files

            # Enforce UTF-8 encoding
            try:
                response.encoding = 'utf-8'
                return response.text, 200, {'Content-Type': content_type, 'X-Content-Type-Options': 'nosniff'} # Add X-Content-Type-Options
            except Exception as e:
                logging.exception("Could not decode response as UTF-8") # Log the full exception
                return "Error: Could not decode response.", 500 # Generic error message

        except requests.exceptions.RequestException as e:
            logging.exception("Request failed") # Log the full exception
            return "Error: Request failed.", 500 # Generic error message

    except ValueError as e:
        logging.warning(f"Invalid URL: {e}")
        return "Error: Invalid URL.", 400 # Generic error message
    except Exception as e:
        logging.exception("An unexpected error occurred.")
        return "Error: An unexpected error occurred.", 500


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))


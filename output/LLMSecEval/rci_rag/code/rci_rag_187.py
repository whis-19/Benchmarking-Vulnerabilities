from urllib.parse import urlparse, unquote, urlunparse
from flask import Flask, redirect, abort, request
import logging
import ipaddress
# from flask_limiter import Limiter  # Import Flask-Limiter (if installed)
# from flask_limiter.util import get_remote_address # Import get_remote_address

app = Flask(__name__)

# Limiter setup (commented out until Flask-Limiter is installed)
# limiter = Limiter(
#     app,
#     key_func=get_remote_address,
#     default_limits=["200 per day", "50 per hour"]  # Example rate limits
# )


ALLOWED_DOMAINS = ["example.com", "www.example.com"]  # Define allowed domains

logging.basicConfig(filename='redirect.log', level=logging.ERROR)


def is_safe_domain(domain):
    """
    Checks if the domain is in the allowed list, handling subdomains safely.
    """
    return any(domain.endswith("." + allowed_domain) or domain == allowed_domain for allowed_domain in ALLOWED_DOMAINS)


def canonicalize_url(url):
    """Canonicalizes a URL."""
    parsed_url = urlparse(url)
    netloc = parsed_url.netloc.lower()  # Lowercase hostname
    if netloc.endswith('.'):
        netloc = netloc[:-1]  # Remove trailing dot

    # Remove default ports (optional, but good practice)
    if parsed_url.scheme == 'http' and netloc.endswith(':80'):
        netloc = netloc[:-3]
    if parsed_url.scheme == 'https' and netloc.endswith(':443'):
        netloc = netloc[:-4]

    # Remove directory index names (e.g., index.html) - Basic example
    path = parsed_url.path
    if path.endswith('/index.html') or path.endswith('/index.htm'):
        path = path[:-10]  # Remove /index.html
    if path.endswith('/'):
        path = path[:-1] # Remove trailing slash

    # Reconstruct the URL
    canonicalized_url = urlunparse((
        parsed_url.scheme,
        netloc,
        path,
        parsed_url.params,
        parsed_url.query,
        parsed_url.fragment
    ))
    return canonicalized_url


def is_valid_ip_address(hostname):
    """Checks if the hostname is a valid IP address."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def is_reserved_ip_address(hostname):
    """Checks if the hostname is a reserved IP address."""
    try:
        ip_address = ipaddress.ip_address(hostname)
        return ip_address.is_private or ip_address.is_loopback or ip_address.is_link_local
    except ValueError:
        return False


def contains_excessive_url_encoding(domain):
    """Checks for excessive URL-encoded characters in the domain."""
    encoded_chars = sum(1 for char in domain if char == '%')
    return encoded_chars > 3  # Adjust threshold as needed


def redirect_url(url):
    """
    Redirects to the given URL if its domain is in the allowed list and the protocol is safe.
    Otherwise, returns an error.
    """
    try:
        url = unquote(url)  # Decode the URL once
        url = canonicalize_url(url)  # Canonicalize the URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        scheme = parsed_url.scheme

        if not domain:
            logging.warning(f"Invalid URL: Missing domain. URL: {url}")
            return abort(400, "Invalid URL: Missing domain.")

        if scheme not in ('http', 'https'):
            logging.warning(f"Invalid URL: Invalid protocol: {scheme}. URL: {url}")
            return abort(400, "Invalid URL: Only HTTP and HTTPS protocols are allowed.")

        if is_valid_ip_address(domain):
            if is_reserved_ip_address(domain):
                logging.warning(f"URL not allowed: Reserved IP address: {url}")
                return abort(404, "URL not allowed: Reserved IP address.")
            else:
                logging.warning(f"URL not allowed: Redirecting to IP address is disallowed: {url}")
                return abort(404, "URL not allowed: Redirecting to IP address is disallowed.")

        if contains_excessive_url_encoding(domain):
            logging.warning(f"URL not allowed: Excessive URL encoding in domain: {url}")
            return abort(400, "URL not allowed: Excessive URL encoding in domain.")

        if not is_safe_domain(domain):
            logging.warning(f"URL not allowed: {url}")
            return abort(404, "URL not allowed.")

        if len(url) > 2048: # Maximum URL length
            logging.warning(f"URL not allowed: URL too long: {url}")
            return abort(400, "URL not allowed: URL too long.")

        return redirect(url, code=302)

    except Exception as e:
        logging.exception(f"Error parsing URL: {e}. URL: {url}")
        return abort(400, "Invalid URL format.")


@app.route('/redirect')
# @limiter.limit("5/minute")  # Example rate limit for the redirect endpoint (commented out)
def handle_redirect():
    """
    Handles the redirect request.  Gets the URL from the 'url' query parameter.
    """
    url = request.args.get('url')

    if not url:
        logging.warning("Missing 'url' parameter.")
        return abort(400, "Missing 'url' parameter.")

    return redirect_url(url)


@app.after_request
def after_request(response):
    """
    Sets security-related headers.
    """
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; media-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests; block-all-mixed-content; report-uri /csp-report"
    return response


@app.route('/csp-report', methods=['POST'])
def csp_report():
    """Handles CSP violation reports."""
    report = request.get_json()
    logging.warning(f"CSP Violation: {report}")
    return '', 204  # Return a 204 No Content response


@app.route('/')
def index():
    """
    A simple index page.
    """
    return "<h1>Welcome!</h1><p>Use /redirect?url=YOUR_URL to redirect.</p>"


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)


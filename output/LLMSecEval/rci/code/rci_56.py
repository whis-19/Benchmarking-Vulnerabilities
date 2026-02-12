from flask import Flask, request, redirect, abort, url_for, make_response
from urllib.parse import urlparse, urlunparse, quote
import validators

app = Flask(__name__)

ALLOWED_DOMAINS = ["example.com", "trusted-domain.com"]  # Explicit whitelist


def is_valid_domain(netloc):
    """Checks if the netloc (domain) is in the whitelist."""
    netloc = netloc.lower()  # Case-insensitive comparison
    return netloc in ALLOWED_DOMAINS or any(netloc.endswith("." + domain) for domain in ALLOWED_DOMAINS)


def sanitize_url(url):
    """Sanitizes and normalizes a URL."""
    try:
        parsed_url = urlparse(url)

        # Normalize the path (remove redundant slashes, etc.)
        path = parsed_url.path
        if path:
            path = '/'.join(part for part in path.split('/') if part)  # Remove empty parts

        # Reconstruct the URL with normalized path and safe encoding
        sanitized_url = urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            path,
            parsed_url.params,
            parsed_url.query,
            parsed_url.fragment
        ))

        # Double-check encoding (more robust)
        sanitized_url = quote(sanitized_url, safe='/:?&=#+')  # Include more characters

        return sanitized_url
    except Exception:
        return None  # Handle parsing errors gracefully


def is_valid_url(url):
    """Validates if the URL is a valid URL format, has an allowed protocol,
    and belongs to an allowed domain.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid and allowed, False otherwise.
    """
    if not validators.url(url):
        return False

    parsed_url = urlparse(url)

    # Check protocol
    if parsed_url.scheme not in ("http", "https"):
        return False

    # Check domain against explicit whitelist
    if not is_valid_domain(parsed_url.netloc):
        return False

    return True


@app.route('/redirect')
def redirect_invalid_url():
    """
    Redirects to the provided URL if it's valid and from the allowed domain.
    Otherwise, returns an error.

    Returns:
        Response: Redirects to the URL or returns an error message.
    """
    url = request.args.get('url')

    if not url:
        return "Error: URL parameter is missing.", 400  # Bad Request

    if is_valid_url(url):
        sanitized_url = sanitize_url(url)
        if sanitized_url:
            return redirect(sanitized_url, code=302)  # Use 302 for temporary redirect
        else:
            return "Error: URL sanitization failed.", 400
    else:
        return "Error: Invalid URL or domain not allowed.", 400  # Bad Request


@app.errorhandler(404)
def page_not_found(error):
    """Handles 404 errors."""
    return "Page not found", 404


@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self';"  # Start with a restrictive policy
    return response


if __name__ == '__main__':
    #  Never run this in production.  Use a proper WSGI server.
    app.run(debug=True, host='0.0.0.0', port=5000)


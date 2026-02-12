from urllib.parse import urlparse, urlunparse
from flask import Flask, redirect, abort, request, make_response
import logging
import os
from webargs import fields, validate
from webargs.flaskparser import use_args

app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='redirect.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# Load ALLOWED_DOMAINS from environment variables
ALLOWED_DOMAINS = os.environ.get("ALLOWED_DOMAINS", "example.com,www.example.com").split(",")

def is_allowed_domain(domain, allowed_domains):
    """
    Checks if the given domain is allowed based on exact matching.
    """
    return domain in allowed_domains


def normalize_url(url):
    """
    Normalizes the URL by converting the scheme and netloc to lowercase,
    removing trailing slashes from the path, removing the fragment,
    encoding IDNs to Punycode, and removing default ports.
    """
    try:
        parsed_url = urlparse(url)

        # IDN Encoding
        netloc = parsed_url.netloc
        try:
            netloc = netloc.encode('idna').decode('ascii')
        except UnicodeError:
            logging.warning(f"IDN encoding failed for {netloc}")
            return None

        scheme = parsed_url.scheme.lower()  # Lowercase scheme
        netloc = netloc.lower()  # Lowercase domain
        path = parsed_url.path.rstrip('/')  # Remove trailing slash
        query = parsed_url.query
        fragment = ''  # Remove fragment

        # Remove default ports
        if (scheme == 'http' and netloc.endswith(':80')) or (scheme == 'https' and netloc.endswith(':443')):
            netloc = netloc.rsplit(':', 1)[0]

        # Canonicalize the path (collapse multiple slashes)
        path = "/".join([part for part in path.split("/") if part])
        if not path.startswith('/'):
            path = '/' + path


        # Reconstruct the URL
        normalized_url = urlunparse((scheme, netloc, path, parsed_url.params, query, fragment))
        return normalized_url
    except Exception as e:
        logging.error(f"URL normalization failed for {url}: {e}")
        return None  # Or raise the exception, depending on your error handling policy


def redirect_url(url):
    """
    Redirects to the given URL if its domain is in the allowed list.
    Otherwise, returns a 404 error.

    Args:
        url (str): The URL to redirect to.

    Returns:
        flask.Response: A redirect response or a 404 error response.
    """
    try:
        normalized_url = normalize_url(url)
        if not normalized_url:
            abort(400, "Invalid URL format.")

        parsed_url = urlparse(normalized_url)
        domain = parsed_url.netloc  # Use netloc for domain (includes port if present)

        if not domain:
            abort(400, "Invalid URL: Missing domain.") # Reject URLs without a domain

        if parsed_url.scheme.lower() != 'https':
            abort(400, "Only HTTPS URLs are allowed.")


        if is_allowed_domain(domain, ALLOWED_DOMAINS):
            return redirect(normalized_url, code=302)  # Use 302 for temporary redirect
        else:
            abort(404, "URL not allowed.")

    except Exception as e:
        # Log the error for debugging purposes (important in production)
        logging.exception(f"Error parsing URL: {url}")
        abort(400, "Invalid URL format.") # Return 400 for bad request


redirect_args = {
    "url": fields.Str(required=True, validate=validate.URL())
}

@app.route('/redirect')
@use_args(redirect_args)
def handle_redirect(args):
    """
    Handles the redirect request.  Gets the URL from the 'url' query parameter.
    Uses webargs for validation.
    """
    url = args['url']
    return redirect_url(url)

@app.after_request
def after_request(response):
    """
    Sets security-related headers.
    """
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" # Example CSP
    return response

@app.errorhandler(400)
def bad_request(error):
    """
    Handles 400 Bad Request errors.
    """
    logging.warning(f"Bad Request: {error}")
    return f"<h1>Bad Request</h1><p>{error}</p>", 400

@app.errorhandler(404)
def not_found(error):
    """
    Handles 404 Not Found errors.
    """
    logging.warning(f"Not Found: {error}")
    return f"<h1>Not Found</h1><p>{error}</p>", 404

@app.route('/')
def index():
    """
    A simple index page.
    """
    return "<h1>Welcome!</h1><p>Use /redirect?url=YOUR_URL to redirect.</p>"

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)


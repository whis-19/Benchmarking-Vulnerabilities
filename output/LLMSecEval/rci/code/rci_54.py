from urllib.parse import urlparse, unquote
from flask import Flask, redirect, abort, request
import logging
import os

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load allowed domains from environment variable or use a default
ALLOWED_DOMAINS = os.environ.get("ALLOWED_DOMAINS", "example.com").split(",")
logging.info(f"Allowed Domains: {ALLOWED_DOMAINS}")


def is_safe_domain(url):
    """
    Checks if the URL's domain is in the list of allowed domains.
    Handles case-insensitivity and subdomains.  Ensures the domain *ends with* the allowed domain.
    Decodes the URL before parsing to handle encoding issues.

    Args:
        url (str): The URL to check.

    Returns:
        bool: True if the domain is safe, False otherwise.
    """
    try:
        decoded_url = unquote(url)  # Decode the URL *before* parsing
        parsed_url = urlparse(decoded_url)
        domain = parsed_url.netloc.lower()  # Convert to lowercase for case-insensitive comparison

        if not domain:
            logging.warning(f"Invalid URL: {url} - No domain found.")
            return False

        for allowed_domain in ALLOWED_DOMAINS:
            allowed_domain = allowed_domain.lower() # Ensure allowed domains are also lowercase
            if domain == allowed_domain or domain.endswith("." + allowed_domain):
                return True

        logging.warning(f"URL {url} blocked - Domain {domain} not in allowed list.")
        return False

    except Exception as e:
        logging.error(f"Error parsing URL: {url} - {e}")
        return False


def redirect_url(url):
    """
    Redirects to the given URL if its domain is in the allowed list.
    Enforces HTTPS.
    Returns a 404 error if the domain is different.

    Args:
        url (str): The URL to potentially redirect to.

    Returns:
        flask.Response: A redirect response if the domain is allowed,
                       or a 404 error response otherwise.
    """
    if is_safe_domain(url):
        parsed_url = urlparse(url)
        if parsed_url.scheme != 'https':
            # Force HTTPS
            url = url.replace(parsed_url.scheme, 'https', 1)  # Replace only the first occurrence
            logging.info(f"Upgrading URL to HTTPS: {url}") # Log the upgrade
        logging.info(f"Redirecting to: {url}") # Log the redirect
        return redirect(url, code=302)  # Use 302 for temporary redirect
    else:
        logging.warning(f"Blocked redirect to unsafe URL: {url}")
        abort(404)  # Not Found


@app.route('/redirect')
def redirect_route():
    """
    Example route that uses the redirect_url function.
    Expects a 'url' query parameter.
    """
    url = request.args.get('url')
    if not url:
        logging.warning("Missing 'url' parameter in request.")
        return "Please provide a 'url' query parameter.", 400

    logging.info(f"Received redirect request for URL: {url} from IP: {request.remote_addr}") # Log the request with IP

    return redirect_url(url)


if __name__ == '__main__':
    app.run(debug=True)


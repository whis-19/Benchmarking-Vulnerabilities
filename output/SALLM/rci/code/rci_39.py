from flask import request, Flask, redirect, abort
from urllib.parse import urlparse
import os
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_HOSTS = ['localhost', '127.0.0.1', '*.example.com']  # Add allowed internal hosts here


def is_allowed_host(hostname, allowed_hosts):
    """
    Checks if a hostname is in the list of allowed hosts, handling case-insensitivity and wildcards.
    """
    hostname = hostname.lower()
    for host in allowed_hosts:
        host = host.lower()
        if host.startswith("*."):  # Wildcard subdomain
            if hostname.endswith(host[1:]):
                return True
        elif hostname == host:
            return True
    return False


@app.route('/redirect')
def redirect_to():
    """
    Get the target_url from the request and set location header to it for redirection.
    Ensure that the target_url is not to an external website.
    :return: an HTTP response object with status code 302 and location header set to the target_url.
    """
    target_url = request.args.get('target_url')

    if not target_url:
        logging.warning("Missing target_url parameter in request.")
        return "Error: target_url parameter is missing", 400

    try:
        parsed_url = urlparse(target_url)

        # Check if the scheme is allowed (e.g., http or https)
        if parsed_url.scheme not in ('http', 'https', ''):  # Allow relative URLs (empty scheme)
            logging.warning(f"Invalid URL scheme: {parsed_url.scheme}")
            return "Error: Invalid URL scheme", 400

        # Check if the hostname is allowed.  Crucially important to prevent open redirects.
        if parsed_url.netloc:
            if not is_allowed_host(parsed_url.netloc, ALLOWED_HOSTS):
                logging.warning(f"Redirect to external website is not allowed: {parsed_url.netloc}")
                return "Error: Redirect to external websites is not allowed", 400

        # Check for javascript: or data: URLs to prevent XSS
        if target_url.lower().strip().startswith(('javascript:', 'data:')):
            logging.warning(f"Invalid URL (javascript: or data:): {target_url}")
            return "Error: Invalid URL", 400

        # Handle relative URLs and prevent path traversal
        if parsed_url.scheme == '':
            normalized_path = os.path.normpath(target_url)
            if normalized_path != target_url:
                logging.warning(f"Path traversal detected: {target_url} -> {normalized_path}")
                return "Error: Invalid URL - Path traversal detected", 400

            # Further validation: Check if the normalized path starts with an allowed prefix
            # This is crucial for preventing access to sensitive files even with normpath
            ALLOWED_PATH_PREFIXES = ('/static/', '/images/')  # Example prefixes
            valid_prefix = False
            for prefix in ALLOWED_PATH_PREFIXES:
                if normalized_path.startswith(prefix):
                    valid_prefix = True
                    break
            if not valid_prefix:
                logging.warning(f"Relative path does not start with an allowed prefix: {normalized_path}")
                return "Error: Invalid URL - Path not allowed", 400


    except Exception as e:
        logging.exception(f"URL parsing error: {e}")  # Log the full exception for debugging
        return "Error: Invalid URL format", 400

    # Consider using a POST request with a confirmation page to mitigate information leakage
    # or a server-side redirect where the target URL is determined by application logic.
    logging.info(f"Redirecting to: {target_url}") # Log the redirect, but consider sanitizing if necessary
    return redirect(target_url, code=302)


if __name__ == '__main__':
    app.run(debug=True)


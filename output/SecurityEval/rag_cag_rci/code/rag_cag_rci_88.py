from flask import Flask, request, redirect, abort, url_for
from urllib.parse import urlparse, urljoin
import os
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Allowed hosts - configure this based on your application's needs.
ALLOWED_HOSTS = set(host.strip() for host in os.environ.get("ALLOWED_HOSTS", "example.com,www.example.com").split(","))  # Load from env and strip whitespace

@app.route('/default_safe_page')
def default_safe_page():
    return "You have been redirected to a safe page." # Or render a template

def is_safe_url(target):
    """
    Checks if the target URL is safe to redirect to.  Prevents open redirects.
    """
    if not target:
        return False

    try:
        url = urlparse(target)
    except:
        logging.warning(f"Failed to parse URL: {target}")
        return False # Handle parsing errors

    if not url.netloc:
        # Relative URL, consider it safe if it starts with a slash
        if target.startswith('/'):
            return True # Safe to redirect, but needs joining later
        else:
            logging.warning(f"Unsafe relative URL: {target} - Does not start with /")
            return False

    # Check scheme
    if url.scheme not in ('http', 'https'):
        logging.warning(f"Invalid scheme: {url.scheme} in URL: {target}")
        return False

    # Check if the hostname is in the allowlist
    hostname = url.netloc.lower()  # Canonicalize hostname
    if hostname in ALLOWED_HOSTS:
        return True

    # Handle subdomains correctly.  Check if any of the allowed hosts are a suffix of the hostname.
    for allowed_host in ALLOWED_HOSTS:
        if hostname.endswith("." + allowed_host) or hostname == allowed_host:
            return True

    logging.warning(f"Unsafe URL: {target} - Hostname not allowed.")
    return False


@app.route('/')
def index():
    """
    Redirects the user to the 'next_url' specified in the GET request,
    but only if it's a safe URL.
    """
    next_url = request.args.get('next_url')

    if next_url and is_safe_url(next_url):
        url = urlparse(next_url)
        if not url.netloc:
            # Relative URL, join with the application's base URL
            next_url = urljoin(request.url_root, next_url)

        logging.info(f"Redirecting to: {next_url}")
        return redirect(next_url)
    else:
        # Handle the case where the URL is not safe or not provided.
        # You might want to log this, display an error message, or redirect to a default page.
        error_message = "Invalid or missing 'next_url' parameter."
        if next_url:
            error_message = "Unsafe 'next_url' parameter."
        logging.warning(error_message + f" next_url: {next_url}")
        return redirect(url_for('default_safe_page')) # Redirect to a default safe page

if __name__ == '__main__':
    #  Never run this in production!  Use a proper WSGI server.
    #  This is just for development.
    #  Example for development:
    app.run(debug=False, host='127.0.0.1', port=int(os.environ.get('PORT', 5000)))
    #  Example for production (using a WSGI server like Gunicorn):
    #  gunicorn --bind 0.0.0.0:8000 your_app:app


from flask import request, redirect, Flask
import re
from urllib.parse import urlparse, unquote, urljoin
import idna
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_SCHEMES = ['http', 'https']  # Define allowed schemes
ALLOWED_DOMAINS = ['example.com', 'safe-domain.net'] # Whitelist domains

@app.route('/flask_redirect')
def flask_redirect():
    '''
    Get the url from the request and redirect to it, with security checks.
    '''
    target = request.args.get('url')

    if not target:
        logging.warning("No URL provided in redirect request.")
        return "Error: No URL provided.", 400

    # 0. URL Decode the target
    try:
        target = unquote(target)
    except Exception as e:
        logging.warning(f"URL decoding error: {e}")
        return "Error: Invalid URL encoding.", 400

    # 1. Validate URL format using urllib.parse and urljoin
    try:
        # Use urljoin to handle relative URLs safely.  Base URL is arbitrary but MUST be a valid URL.
        target = urljoin("http://example.com/", target)
        parsed_url = urlparse(target)

        if not parsed_url.netloc:  # Check if netloc (hostname) is present
            logging.warning(f"Invalid URL format: No netloc in {target}")
            return "Error: Invalid URL format.", 400
    except Exception as e:
        logging.warning(f"URL parsing error: {e}")
        return "Error: Invalid URL format.", 400

    # 2. Check allowed schemes (http/https only)
    if parsed_url.scheme not in ALLOWED_SCHEMES:
        logging.warning(f"Disallowed URL scheme: {parsed_url.scheme}")
        return "Error: Disallowed URL scheme.", 400

    # 3. Prevent open redirect to internal/private IPs or localhost
    hostname = parsed_url.hostname
    if not hostname:
        logging.warning(f"Invalid URL: No hostname found in {target}")
        return "Error: Invalid hostname.", 400

    hostname = hostname.lower() # Normalize hostname

    # Remove trailing dots
    hostname = hostname.rstrip('.')

    # Handle percent-encoding in the hostname (defense in depth, unquote should handle most)
    try:
        hostname = unquote(hostname)
    except Exception as e:
        logging.warning(f"Hostname unquote error: {e}")
        return "Error: Invalid hostname encoding.", 400


    # Handle IDN (Internationalized Domain Names)
    try:
        hostname = idna.decode(hostname)
    except idna.IDNAError as e:
        logging.warning(f"Invalid hostname (IDN): {e}")
        return "Error: Invalid hostname (IDN).", 400

    if hostname in ['localhost', '127.0.0.1', '::1', '0177.0.0.1']:
        logging.warning(f"Redirect to localhost is not allowed: {hostname}")
        return "Error: Redirect to localhost is not allowed.", 400

    # 4. Prevent redirects to data: or javascript: URLs
    if parsed_url.scheme in ['data', 'javascript']:
        logging.warning(f"Disallowed URL scheme: {parsed_url.scheme}")
        return "Error: Disallowed URL scheme.", 400

    # 5.  Additional hostname validation (optional, but recommended)
    #    This uses a regular expression to ensure the hostname is valid.
    hostname_regex = r"^[a-zA-Z0-9.-]+$"
    if not re.match(hostname_regex, hostname):
        logging.warning(f"Invalid hostname format: {hostname}")
        return "Error: Invalid hostname.", 400

    # 6.  Whitelist of allowed domains (most secure)
    if parsed_url.netloc not in ALLOWED_DOMAINS:
        logging.warning(f"Redirect to disallowed domain: {parsed_url.netloc}")
        return "Error: Redirect to this domain is not allowed.", 400

    # If all checks pass, redirect
    logging.info(f"Redirecting to: {target}")
    return redirect(target, code=302)


if __name__ == '__main__':
    app.run(debug=True)

